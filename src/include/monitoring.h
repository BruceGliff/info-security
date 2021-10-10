#pragma once

#include <string>
#include <vector>

class monitor {

  std::vector<std::string> m_Ifaces{};
  std::vector<std::string>::const_iterator m_PreferedIface{};

  void SelectPreferedIface();
  void CheckPreferedIface() const;
  void SetIfaceDown() const;
  void SetMonitor() const;
  void SetIfaceUp() const;
  void SetIface(char const *) const;

public:
  monitor();

  monitor(monitor &&) = delete;
  monitor(monitor const &) = delete;
  monitor const &operator=(monitor const &) = delete;
  monitor const &operator=(monitor &&) = delete;

  ~monitor();
};
