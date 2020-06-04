#pragma once

template <typename... Args>
class event {
  using func_type = std::function<void(Args...)>;

  std::mutex event_lock;
  std::list<func_type> m_funcs;

 public:
  void add(const func_type& func) {
    std::lock_guard<std::mutex> lock(event_lock);

    m_funcs.push_back(std::move(func));
  }

  void call(Args... params) {
    std::lock_guard<std::mutex> lock(event_lock);

    for (auto& func : m_funcs) {
      if (func) func(std::forward<Args>(params)...);
    }
  }
};