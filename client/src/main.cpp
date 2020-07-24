#include "include.h"
#include "util/io.h"
#include "util/util.h"
#include "util/syscalls.h"
#include "client/client.h"
#include "injection/process.h"
#include "injection/mapper.h"

int main(int argc, char* argv[]) {
	io::init();

	if (!util::init()) {
		return 0;
	}

	g_syscalls.init();

	tcp::client client;

	std::thread t{ tcp::client::monitor, std::ref(client) };
	t.detach();

	std::thread t1{ mmap::thread, std::ref(client) };
	t1.detach();

	client.start("127.0.0.1", 6666);

	client.connect_event.add([&]() { io::logger->info("connected."); });

	client.receive_event.add([&](tcp::packet_t& packet) {
		if (!packet) return;
		auto message = packet();
		auto id = packet.id;

		if (id == tcp::packet_id::session) {
			client.session_id = packet.session_id;

			tcp::version_t v{ 0, 1, 0 };
			auto version = fmt::format("{}.{}.{}", v.major, v.minor, v.patch);
			io::logger->info("current server version {}", message);

			if (version != message) {
				io::logger->error("please update your client.");
				client.shutdown();

				return;
			}

			int ret =
				client.write(tcp::packet_t("hwid", tcp::packet_type::write,
					client.session_id, tcp::packet_id::hwid));
			if (ret <= 0) {
				io::logger->error("failed to send hwid.");
				client.shutdown();
				return;
			}
		}

		if (id == tcp::packet_id::login_resp) {
			auto j = nlohmann::json::parse(message);

			auto res = j["result"].get<int>();

			if (res == tcp::login_result::banned) {
				io::logger->error("your account is banned.");
				client.shutdown();
				return;
			}

			if (res == tcp::login_result::login_fail) {
				io::logger->error("please check your username or password.");
				client.shutdown();
				return;
			}

			if (res == tcp::login_result::hwid_mismatch) {
				io::logger->error("please reset your hwid on the forums.");
				client.shutdown();
				return;
			}

			if (res == tcp::login_result::server_error) {
				io::logger->error("internal server error, please contact a developer.");
				client.shutdown();
				return;
			}

			if (res == tcp::login_result::login_success) {
				auto games = j["games"];
				for (auto& [key, value] : games.items()) {
					std::string version = value["version"];
					int id = value["id"];

					client.games.emplace_back(tcp::game_data_t{ key, version, id });
				}

				io::logger->info("logged in.");
				client.state = tcp::client_state::logged_in;
			}
		}

		if (id == tcp::packet_id::game_select) {
			auto j = nlohmann::json::parse(message);
			client.mapper_data.image_size = j["pe"][0];
			client.mapper_data.entry = j["pe"][1];

			client.read_stream(client.mapper_data.imports);

			client.state = tcp::client_state::waiting;
		}

		if (id == tcp::packet_id::image) {
			client.read_stream(client.mapper_data.image);

			io::logger->info("got image");
		}


		if (id == tcp::packet_id::ban) {
			io::logger->error(
				"your computer is blacklisted, please contact a developer.");
			client.shutdown();
			return;
		}

		io::logger->info("{}:{}->{} {}", packet.seq, packet.session_id, message, id);
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
				break;
			}
		}

		if (client.state == tcp::client_state::logged_in) {
			for (auto& dat : client.games) {
				io::logger->info("[{}]{} : {}", dat.id, dat.name, dat.version);
			}
			io::logger->info("please select a game :");

			int id;
			std::cin >> id;

			nlohmann::json j;
			j["id"] = id;

			int ret = client.write(tcp::packet_t(j.dump(), tcp::packet_type::write,
				client.session_id,
				tcp::packet_id::game_select));

			if (ret <= 0) {
				break;
			}

			break;
		}

	}

	while (client) {
		std::this_thread::sleep_for(std::chrono::seconds(1));
	}


	std::cin.get();
}
