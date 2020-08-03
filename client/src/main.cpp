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
#include "ui/ui.h"


bool init(tcp::client& client) {
	client.start("127.0.0.1", 6666);

	if (!client) {
		return false;
	}

	client.connect_event.add([&]() { io::log("connected."); });

	client.receive_event.add([&](tcp::packet_t& packet) {
		if (!packet) return;
		auto message = packet();
		auto id = packet.id;

		if (id == tcp::packet_id::session) {
			client.session_id = packet.session_id;

			uint16_t ver{ 0 };
			for (int i = 0; i < message.size(); ++i) {
				if (i % 2) { // skip characters in between
					continue;
				}

				ver += static_cast<uint8_t>(message[i]) << 5;
			}

			if (client.ver != ver) {
				client.session_result = tcp::session_result::version_mismatch;

				std::this_thread::sleep_for(std::chrono::seconds(5));

				client.shutdown();
				return;
			}

			auto hwid = hwid::fetch();

			int ret = client.write(tcp::packet_t(hwid, tcp::packet_type::write, client.session_id, tcp::packet_id::hwid));
			if (ret <= 0) {
				client.session_result = tcp::session_result::hwid_fail;

				std::this_thread::sleep_for(std::chrono::seconds(5));

				client.shutdown();
				return;
			}

			client.state = tcp::client_state::idle;
		}

		if (id == tcp::packet_id::login_resp) {
			auto j = nlohmann::json::parse(message);

			client.login_result = j["result"].get<int>();

			if (client.login_result == tcp::login_result::login_success) {
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
}

int WinMain(HINSTANCE inst, HINSTANCE prev_inst, LPSTR cmd_args, int show_cmd) {
	AllocConsole();

	FILE* fp = nullptr;
	freopen_s(&fp, "CONIN$", "r", stdin);
	freopen_s(&fp, "CONOUT$", "w", stdout);
	freopen_s(&fp, "CONOUT$", "w", stderr);

	g_syscalls.init();

	tcp::client client;

	if (!init(client)) {
		MessageBoxA(0, "Server error.", "client", MB_OK);


		return 0;
	}

	std::thread mon{ tcp::client::monitor, std::ref(client) };
	mon.detach();

	std::thread mapper_thread{ mmap::thread, std::ref(client) };
	mapper_thread.detach();

	std::thread sec_thread{ security::thread, std::ref(client) };
	sec_thread.detach();

	auto hwnd = ui::create(inst, { 430, 330 });

	if (!ui::create_device(hwnd)) {
		io::log_error("failed to create device.");

		std::cin.get();

		return 0;
	}


	ShowWindow(hwnd, show_cmd);

	ImGui::CreateContext();

	ImGui::StyleColorsDark();

	ImGui::GetIO().IniFilename = nullptr;

	ImGui_ImplWin32_Init(hwnd);
	ImGui_ImplDX11_Init(ui::device, ui::device_context);

	MSG msg;
	std::memset(&msg, 0, sizeof(msg));
	while (msg.message != WM_QUIT) {
		if (PeekMessage(&msg, NULL, 0U, 0U, PM_REMOVE)) {
			TranslateMessage(&msg);
			DispatchMessage(&msg);
			continue;
		}

		if (!client)
			break;

		// Start the Dear ImGui frame
		ImGui_ImplDX11_NewFrame();
		ImGui_ImplWin32_NewFrame();
		ImGui::NewFrame();

		ImGui::SetNextWindowSize(ImVec2{400, 250}, ImGuiCond_::ImGuiCond_Always);
		ImGui::SetNextWindowPos(ImVec2{0, 0}, ImGuiCond_::ImGuiCond_Always);
		ImGui::Begin("##main", 0, ImGuiWindowFlags_NoTitleBar | ImGuiWindowFlags_NoCollapse | ImGuiWindowFlags_NoMove |
			ImGuiWindowFlags_NoResize | ImGuiWindowFlags_NoSavedSettings | ImGuiWindowFlags_MenuBar);


		if (client.state == tcp::client_state::connecting) {
			if (client.session_result == -1) {
				ImGui::Text("connecting...");
			}
			
			if (client.session_result == tcp::session_result::hwid_fail) {
				ImGui::Text("internal client error.");
			}

			if (client.session_result == tcp::session_result::version_mismatch) {
				ImGui::Text("please update your client.");
			}
		}

		if (client.state == tcp::client_state::idle) {
			static std::array<char, 128> u;
			ImGui::InputText("Username", &u[0], u.size());

			static std::array<char, 128> p;
			ImGui::InputText("Password", &p[0], p.size());

			if (ImGui::Button("login")) {
				auto l = fmt::format("{},{}", u.data(), p.data());

				int ret = client.write(tcp::packet_t(l, tcp::packet_type::write,
					client.session_id,
					tcp::packet_id::login_req));

				if (ret <= 0) {
					ImGui::Text("failed to send request, please try again.");
				}
			}

			auto res = client.login_result;
			if (res != -1) {
				if (res == tcp::login_result::banned) {
					MessageBoxA(hwnd, "your account is banned.", "client", MB_OK);

					client.shutdown();
					break;
				}

				if (res == tcp::login_result::login_fail) {
					ImGui::Text("please check your username or password.");
				}

				if (res == tcp::login_result::hwid_mismatch) {
					MessageBoxA(hwnd, "please reset your hwid on the forums.", "client", MB_OK);

					client.shutdown();
					break;
				}

				if (res == tcp::login_result::server_error) {
					MessageBoxA(hwnd, "internal server error, please contact a developer.", "client", MB_OK);

					client.shutdown();
					break;
				}

				if (res == tcp::login_result::login_success) {
					ImGui::Text("logged in.");
				}
			}
		}

		if (client.state == tcp::client_state::logged_in) {
			ImGui::BeginChild("list", ImVec2(150, 300));
			static auto getter = [](void* data, int idx, const char** out_text) -> bool {
				auto game_data = reinterpret_cast<game_data_t*>(data);
				if (out_text)
					*out_text = game_data[idx].name.c_str();
				return true;
			};

			static int i = -1;
			ImGui::ListBox("##dd", &i, getter, (void*)client.games.data(), client.games.size());
			ImGui::EndChild();

			ImGui::SameLine();

			ImGui::BeginChild("dat", ImVec2(250, 300));
			if (i >= 0 && i < client.games.size()) {
				auto game = client.games[i];
				ImGui::Text("version %d", game.version);

				if (ImGui::Button("inject")) {
					client.selected_game = game;

					nlohmann::json j;
					j["id"] = client.selected_game.process_name;
					j["x64"] = client.selected_game.x64;

					int ret = client.write(tcp::packet_t(j.dump(), tcp::packet_type::write,
						client.session_id,
						tcp::packet_id::game_select));

					if (ret <= 0) {
						ImGui::Text("Failed to send request, please try again.");
					}

					client.state = tcp::client_state::waiting;
				}
			}
			ImGui::EndChild();
		}

		if (client.state == tcp::client_state::waiting) {
			ImGui::Text("please wait.");
		}

		if (client.state == tcp::client_state::imports_ready) {
			ImGui::Text("please wait.");
		}

		if (client.state == tcp::client_state::image_ready) {
			ImGui::Text("please wait.");
		}


		if (client.state == tcp::client_state::injected) {
			ImGui::Text("done.");
		}

		ImGui::End();

		ImGui::Render();
		ui::device_context->OMSetRenderTargets(1, &ui::main_render_target, NULL);
		ImGui_ImplDX11_RenderDrawData(ImGui::GetDrawData());

		ui::swap_chain->Present(1, 0);
	}

	ImGui_ImplDX11_Shutdown();
	ImGui_ImplWin32_Shutdown();
	ImGui::DestroyContext();
}
