#pragma once

#include <string>
#include <vector>

class Monitor {

  std::vector<std::string> m_Ifaces{};
  std::vector<std::string>::const_iterator m_PreferedIface{};
  std::string m_Monitor{};

  void SelectPreferedIface();
  bool CheckIfaceForValue(std::string const &iface, int value) const;
  void SetMonitor() const;
  void SetIfaceDown(std::string const &iface) const;
  void SetIfaceUp(std::string const &iface) const;
  void SetIface(std::string const &iface, char const *) const;

public:
  Monitor();

  Monitor(Monitor &&) = delete;
  Monitor(Monitor const &) = delete;
  Monitor const &operator=(Monitor const &) = delete;
  Monitor const &operator=(Monitor &&) = delete;
  
  ~Monitor();

  char const * GetIface() const;
};
