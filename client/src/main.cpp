#include "include.h"
#include "util/io.h"
#include "util/util.h"
#include "util/syscalls.h"
#include "client/client.h"
#include "injection/process.h"
#include "injection/mapper.h"
#include "hwid/hwid.h"
#include "util/apiset.h"
#include "security/security.h"

int main(int argc, char* argv[]) {
	tcp::client client;

	std::thread sec_thread{ security::thread, std::ref(client) };
	sec_thread.join();

	client.start("127.0.0.1", 6666);

	if (!client) {
		io::log_error("failed to start client.");

		io::log("press enter...");

		std::cin.get();

		return 0;
	}

	client.connect_event.add([&]() { io::log("connected."); });

	std::thread t{ tcp::client::monitor, std::ref(client) };
	t.detach();

	std::thread mapper_thread{ mmap::thread, std::ref(client) };
	mapper_thread.detach();

	/*std::thread sec_thread{ security::thread, std::ref(client) };
	sec_thread.detach();*/

	client.receive_event.add([&](tcp::packet_t& packet) {
		if (!packet) return;
		auto message = packet();
		auto id = packet.id;

		if (id == tcp::packet_id::session) {
			client.session_id = packet.session_id;

			uint16_t ver{0};
			for (int i = 0; i < message.size(); ++i) {
				if (i % 2) { // skip characters in between
					continue;
				}

				ver += static_cast<uint8_t>(message[i]) << 5;
			}

			if (client.ver != ver) {
				io::log_error("please update your client.");
				client.shutdown();
				return;
			}

			auto hwid = hwid::fetch();
			int ret = client.write(tcp::packet_t(hwid, tcp::packet_type::write, client.session_id, tcp::packet_id::hwid));
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
					uint8_t version = value["version"];
					std::string process = value["process"];
					uint8_t id = value["id"];
					bool x64 = value["x64"];

					client.games.emplace_back(game_data_t{ x64, id, version, key, process });
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

	std::string u;
	getline(std::cin, u);

	std::string p;
	getline(std::cin, p);

	auto l = fmt::format("{},{}", u, p);

	int ret = client.write(tcp::packet_t(l, tcp::packet_type::write,
		client.session_id,
		tcp::packet_id::login_req));

	if (ret <= 0) {
		io::log_error("failed to send login req packet.");
		client.shutdown();

		io::log("press enter...");

		std::cin.get();

		return 0;
	}

	while (client.state != tcp::client_state::logged_in) {
		if (!client) {
			io::log("press enter...");

			std::cin.get();

			return 0;
		}

		std::this_thread::sleep_for(std::chrono::seconds(1));
	}

	for (auto& dat : client.games) {
		io::log("[{}]{} : {}", dat.id, dat.name, dat.version);
	}

	io::log("please select a game :");

	int id;
	std::cin >> id;
	std::cin.ignore();

	auto it = std::find_if(client.games.begin(), client.games.end(), [&](game_data_t& dat) {
		return dat.id == id;
	});
	client.selected_game = *it;

	nlohmann::json j;
	j["id"] = client.selected_game.process_name;
	j["x64"] = client.selected_game.x64;

	ret = client.write(tcp::packet_t(j.dump(), tcp::packet_type::write,
		client.session_id,
		tcp::packet_id::game_select));

	if (ret <= 0) {
		io::log_error("failed to send game select packet.");
		client.shutdown();

		io::log("press enter...");

		std::cin.get();

		return 0;
	}

	client.state = tcp::client_state::waiting;

	while (client) {
		std::this_thread::sleep_for(std::chrono::seconds(5));
	}

	io::log("press enter...");

	std::cin.get();

	return 0;
}
