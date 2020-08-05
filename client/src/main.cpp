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

void add_handlers(tcp::client& client) {
	client.connect_event.add([&]() { io::log("connected."); });

	client.receive_event.add([&](tcp::packet_t packet) {
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

			hwid::hwid_data_t data;
			if (!hwid::fetch(data)) {
				client.session_result = tcp::session_result::hwid_fail;

				std::this_thread::sleep_for(std::chrono::seconds(5));

				client.shutdown();
				return;
			}

			nlohmann::json json;
			json["uid"] = data.uid;
			json["gpu"] = data.gpu;

			int ret = client.write(tcp::packet_t(json.dump(), tcp::packet_type::write, client.session_id, tcp::packet_id::hwid));
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
			client.shutdown();

			return;
		}

		io::log("{}:{}->{} {}", packet.seq, packet.session_id, message, id);
		});
}

int WinMain(HINSTANCE inst, HINSTANCE prev_inst, LPSTR cmd_args, int show_cmd) {
	FILE* fp = nullptr;
	freopen_s(&fp, "log", "w", stdout);

	g_syscalls.init();

	tcp::client client;

	client.start("127.0.0.1", 6666);

	if (!client) {
		MessageBoxA(0, "failed to connect to the the server..", "client", MB_OK);

		return 0;
	}

	add_handlers(client);

	auto hwnd = ui::create(inst, { 400, 300 });

	if (!ui::create_device(hwnd)) {
		MessageBoxA(0, "internal graphics error, please check your video drivers.", "client", MB_OK);

		return 0;
	}

	std::thread mon{ tcp::client::monitor, std::ref(client) };
	mon.detach();

	std::thread mapper_thread{ mmap::thread, std::ref(client) };
	mapper_thread.detach();

	std::thread sec_thread{ security::thread, std::ref(client) };
	sec_thread.detach();

	ShowWindow(hwnd, show_cmd);

	ImGui::CreateContext();

	ImGui::StyleColorsDark();

	ImGui::GetIO().IniFilename = nullptr;
	ImGui::GetStyle().WindowRounding = 0.f;

	ImGui_ImplWin32_Init(hwnd);
	ImGui_ImplDX11_Init(ui::device, ui::device_context);

	int offset_x = 0;
	int offset_y = 0;

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

		ImGui_ImplDX11_NewFrame();
		ImGui_ImplWin32_NewFrame();
		ImGui::NewFrame();

		if (ImGui::IsMouseClicked(0)) {
			POINT point;
			RECT rect;

			GetCursorPos(&point);
			GetWindowRect(hwnd, &rect);

			offset_x = point.x - rect.left;
			offset_y = point.y - rect.top;
		}

		ImGui::SetNextWindowSize(ImVec2{ 400, 300 }, ImGuiCond_::ImGuiCond_Always);
		ImGui::SetNextWindowPos(ImVec2{ 0, 0 }, ImGuiCond_::ImGuiCond_Always);


		ImGui::Begin("##main", 0, ImGuiWindowFlags_NoCollapse | ImGuiWindowFlags_NoTitleBar | ImGuiWindowFlags_NoMove |
			ImGuiWindowFlags_NoResize | ImGuiWindowFlags_NoSavedSettings | ImGuiWindowFlags_MenuBar | ImGuiWindowFlags_NoScrollbar);

		if (ImGui::BeginMenuBar()) {
			ImGui::Text("client");
			ImGui::EndMenuBar();
		}

		if (ImGui::IsMouseDragging(ImGuiMouseButton_::ImGuiMouseButton_Left)) {
			POINT point;
			GetCursorPos(&point);

			SetWindowPos(hwnd, nullptr, point.x - offset_x, point.y - offset_y, 0, 0, SWP_NOSIZE | SWP_NOZORDER);
		}

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
			static std::string u;
			ImGui::Text("username :");
			ImGui::InputText("##username", &u);

			static std::string p;
			ImGui::Text("password :");
			ImGui::InputText("##password", &p, ImGuiInputTextFlags_Password);

			if (ImGui::Button("login")) {
				auto l = fmt::format("{},{}", u, p);

				int ret = client.write(tcp::packet_t(l, tcp::packet_type::write,
					client.session_id,
					tcp::packet_id::login_req));

				if (ret <= 0) {
					ImGui::Text("failed to send request, please try again.");
				}
				else {
					client.state = tcp::client_state::logging_in;
				}
			}

			if (ImGui::Button("exit")) {
				client.shutdown();
			}
		}

		if (client.state == tcp::client_state::logging_in) {
			auto res = client.login_result;
			if (res == -1) {
				ImGui::Text("logging in...");
			}
			else {
				if (res == tcp::login_result::banned) {
					ImGui::Text("your account is banned.");

					std::this_thread::sleep_for(std::chrono::seconds(5));

					client.shutdown();
					break;
				}

				if (res == tcp::login_result::login_fail) {
					ImGui::Text("please check your username or password.");
				}

				if (res == tcp::login_result::hwid_mismatch) {
					ImGui::Text("please reset your hwid on the forums.");

					std::this_thread::sleep_for(std::chrono::seconds(5));

					client.shutdown();
					break;
				}

				if (res == tcp::login_result::server_error) {
					ImGui::Text("internal server error, please contact a developer.");

					std::this_thread::sleep_for(std::chrono::seconds(5));

					client.shutdown();
					break;
				}

				if (res == tcp::login_result::login_success) {
					ImGui::Text("logged in.");
				}
			}
		}

		if (client.state == tcp::client_state::logged_in) {
			ImGui::BeginChild("list", ImVec2(150, 0), true);
			static int selected = 0;
			for (int i = 0; i < client.games.size(); i++) {
				auto& game = client.games[i];
				if (ImGui::Selectable(game.name.c_str(), selected == i)) {
					selected = i;
				}
			}
			ImGui::EndChild();

			ImGui::SameLine();

			ImGui::BeginGroup();
			ImGui::BeginChild("data", ImVec2(0, -ImGui::GetFrameHeightWithSpacing()));
			auto game = client.games[selected];
			ImGui::Text("%s", game.name);
			ImGui::Separator();

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
			}

			ImGui::EndChild();
			if (ImGui::Button("exit")) {
				client.shutdown();
			}
			ImGui::EndGroup();
		}

		if (client.state == tcp::client_state::waiting) {
			ImGui::Text("waiting for the process...");
		}

		if (client.state == tcp::client_state::imports_ready) {
			ImGui::Text("please wait...");
		}

		if (client.state == tcp::client_state::image_ready) {
			ImGui::Text("please wait...");
		}


		if (client.state == tcp::client_state::injected) {
			ImGui::Text("done.");
		}

		ImGui::End();

		ImGui::Render();
		ui::device_context->OMSetRenderTargets(1, &ui::main_render_target, NULL);
		ImGui_ImplDX11_RenderDrawData(ImGui::GetDrawData());

		ui::swap_chain->Present(0, 0);
	}

	ImGui_ImplDX11_Shutdown();
	ImGui_ImplWin32_Shutdown();
	ImGui::DestroyContext();
}
