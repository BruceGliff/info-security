#pragma once

#include <string>
#include <vector>

class monitor {

  std::vector<std::string> m_Ifaces{};
  std::vector<std::string>::const_iterator m_PreferedIface{};

  void SelectPreferedIface();
  bool CheckIfaceForValue(std::string const &iface, int value) const;
  void SetMonitor() const;
  void SetIfaceDown(std::string const &iface) const;
  void SetIfaceUp(std::string const &iface) const;
  void SetIface(std::string const &iface, char const *) const;

public:
  monitor();

  monitor(monitor &&) = delete;
  monitor(monitor const &) = delete;
  monitor const &operator=(monitor const &) = delete;
  monitor const &operator=(monitor &&) = delete;

  ~monitor();
};
