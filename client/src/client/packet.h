#pragma once
#include "enc.h"

#include <json.hpp>

namespace tcp {
	constexpr size_t session_id_len = 10;
	constexpr size_t message_len = 512;

	enum packet_type { write = 0, read };

	enum packet_id {
		message = 0,
		hwid,
		hwid_resp,
		session,
		login_req,
		login_resp,
		security_report,
		ban,
		game_select,
		image
	};

	struct packet_t {
		uint8_t seq;
		uint8_t id; 
		std::string message;
		std::string session_id;

		packet_t() {}
		packet_t(const std::string_view msg, const packet_type type,
			std::string_view session = "",
			const packet_id action = packet_id::message) {
			if (type == read) {
				++seq;

				message = msg;
				enc::decrypt_message(message);

				auto json = nlohmann::json::parse(message);

				id = json["id"];
				message = json["message"];
				session_id = json["session_id"];
			}
			else {
				nlohmann::json json;
				json["id"] = action;
				json["session_id"] = session;
				json["message"] = msg.data();

				message = json.dump();
				if (message.size() > message_len) {
					message.clear();
					return;
				}

				session_id = session;
				id = action;

				enc::encrypt_message(message);
			}
		}

		~packet_t() {
			message.clear();
			session_id.clear();
			id = -1;
		}

		operator bool() const {
			return !message.empty() && !session_id.empty() && id != -1;
		}
		auto& operator()() { return message; }
	};
};  // namespace tcp
