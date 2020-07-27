#include "include.h"
#include "util/io.h"
#include "util/util.h"
#include "util/syscalls.h"
#include "client/client.h"
#include "injection/process.h"
#include "injection/mapper.h"
#include "hwid/hwid.h"
#include "util/apiset.h"

int main(int argc, char* argv[]) {
	io::log("{:x}", g_syscalls());

	tcp::client client;

	std::thread t{ tcp::client::monitor, std::ref(client) };
	t.detach();

	std::thread t1{ mmap::thread, std::ref(client) };

	client.start("127.0.0.1", 6666);

	client.connect_event.add([&]() { io::log("connected."); });

	client.receive_event.add([&](tcp::packet_t& packet) {
		if (!packet) return;
		auto message = packet();
		auto id = packet.id;

		if (id == tcp::packet_id::session) {
			client.session_id = packet.session_id;

			tcp::version_t v{ 0, 1, 0 };
			auto version = fmt::format("{}.{}.{}", v.major, v.minor, v.patch);
			io::log("current server version {}.", message);

			if (version != message) {
				io::log_error("please update your client.");
				client.shutdown();
				return;
			}

			auto hwid = hwid::fetch();
			int ret =
				client.write(tcp::packet_t(hwid, tcp::packet_type::write,
					client.session_id, tcp::packet_id::hwid));
			if (ret <= 0) {
				io::log_error("failed to send hwid.");
				client.shutdown();
				return;
			}
		}

		if (id == tcp::packet_id::login_resp) {
			auto j = nlohmann::json::parse(message);

			auto res = j["result"].get<int>();

			if (res == tcp::login_result::banned) {
				io::log_error("your account is banned.");
				client.shutdown();
				return;
			}

			if (res == tcp::login_result::login_fail) {
				io::log_error("please check your username or password.");
				client.shutdown();
				return;
			}

			if (res == tcp::login_result::hwid_mismatch) {
				io::log_error("please reset your hwid on the forums.");
				client.shutdown();
				return;
			}

			if (res == tcp::login_result::server_error) {
				io::log_error("internal server error, please contact a developer.");
				client.shutdown();
				return;
			}

			if (res == tcp::login_result::login_success) {
				auto games = j["games"];
				for (auto& [key, value] : games.items()) {
					std::string version = value["version"];
					std::string process = value["process"];
					uint8_t id = value["id"];

					client.games.emplace_back(game_data_t{ key, version, process, id });
				}

				io::log("logged in.");
				client.state = tcp::client_state::logged_in;
			}
		}

		if (id == tcp::packet_id::game_select) {
			auto j = nlohmann::json::parse(message);
			client.mapper_data.image_size = j["pe"][0];
			client.mapper_data.entry = j["pe"][1];
			int imports_size = j["size"];

			int size = client.read_stream(client.mapper_data.imports);
			if (size == imports_size) {
				io::log("got imports");
				client.state = tcp::client_state::imports_ready;
			}
		}

		if (id == tcp::packet_id::image) {
			int size = client.read_stream(client.mapper_data.image);

			if (size == client.mapper_data.image_size) {
				io::log("got image");
				client.state = tcp::client_state::image_ready;
			}
		}

		if (id == tcp::packet_id::ban) {
			io::log_error("your computer is blacklisted, please contact a developer.");
			client.shutdown();
			return;
		}

		io::log("{}:{}->{} {}", packet.seq, packet.session_id, message, id);
	});

	while (client) {
		if (client.state == tcp::client_state::idle) {
			std::string u;
			getline(std::cin, u);

			std::string p;
			getline(std::cin, p);

			if (client.state == tcp::client_state::logged_in)
				continue;

			auto l = fmt::format("{},{}", u, p);

			int ret = client.write(tcp::packet_t(l, tcp::packet_type::write,
				client.session_id,
				tcp::packet_id::login_req));

			if (ret <= 0) {
				client.shutdown();
				break;
			}
		}

		if (client.state == tcp::client_state::logged_in) {
			for (auto& dat : client.games) {
				io::log("[{}]{} : {}", dat.id, dat.name, dat.version);
			}

			io::log("please select a game :");

			int id;
			std::cin >> id;

			auto it = std::find_if(client.games.begin(), client.games.end(), [&](game_data_t& dat) {
				return dat.id == id;
			});
			client.selected_game = *it;

			nlohmann::json j;
			j["id"] = id;

			int ret = client.write(tcp::packet_t(j.dump(), tcp::packet_type::write,
				client.session_id,
				tcp::packet_id::game_select));

			if (ret <= 0) {
				client.shutdown();
				break;
			}

			client.state = tcp::client_state::waiting;
			break;
		}
	}

	t1.join();
}
