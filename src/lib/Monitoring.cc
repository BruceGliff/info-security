#include <Monitoring.h>

#include <cassert>
#include <dirent.h>
#include <fstream>
#include <iostream>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

Monitor::Monitor() {
  struct dirent *wlan_dir{};
  DIR *wlans_dir = opendir("/sys/class/net/");
  assert(wlans_dir && "cannot open /sys/class/net/");

  while ((wlan_dir = readdir(wlans_dir))) {
    std::string Iwlan{wlan_dir->d_name};
    if (Iwlan.compare("wlan") > 0)
      m_Ifaces.push_back(Iwlan);
  }
  closedir(wlans_dir);

  SelectPreferedIface();
  assert(CheckIfaceForValue(*m_PreferedIface, 1) &&
         "interface already in Monitor mode");
  m_Monitor = *m_PreferedIface + "mon";
  SetMonitor();
  m_IsOn = true;
}

void Monitor::SelectPreferedIface() {
  assert(m_Ifaces.size() && "no available interfaces.");
  std::cout << " Iface idx | Iface name\n";
  for (unsigned i = 0, e = m_Ifaces.size(); i != e; ++i) {
    std::cout << "    [" <<  i << "]    |    " << m_Ifaces.at(i) << std::endl;
  }
  bool isSelectBad = true;
  unsigned value {0};
  while (isSelectBad) {
    std::cout << "\nEnter interface index: ";
    std::cin.clear();
    std::cin >> value;
    isSelectBad = !(value < m_Ifaces.size());
  }
  m_PreferedIface = m_Ifaces.begin() + value;
}

bool Monitor::CheckIfaceForValue(std::string const &iface, int value) const {
  std::string fullpath =
      std::string{"/sys/class/ieee80211/phy0/device/net/"} + iface + "/type";

  std::ifstream monvalue{fullpath};
  if (!monvalue.is_open()) {
    std::cerr << "cannot open file: " << fullpath << "\n";
    return false;
  }

  int val{0};
  monvalue >> val;
  return val == value;
}

void Monitor::SetIfaceDown(std::string const &iface) const {
  SetIface(iface, "down");
}
void Monitor::SetIfaceUp(std::string const &iface) const {
  SetIface(iface, "up");
}

void Monitor::SetIface(std::string const &iface, char const *status) const {
  pid_t pid = fork();
  if (pid == 0) {
    char const *params[] = {"ip",          "link", "set", "dev",
                            iface.c_str(), status, 0};
    char *const *p = const_cast<char *const *>(params);
    int ret = execv("/usr/sbin/ip", p);
    perror("execv: ");
    assert(ret != 1 && "cannot set interface down");
  }

  assert(pid && "fork failed\n");
  int ret{99};
  wait(&ret);
  assert(ret == 0 && "ip failed");
}
void Monitor::SetMonitor() const {
  SetIfaceDown(*m_PreferedIface);
  pid_t pid = fork();
  if (pid == 0) {
    char const *params[] = {"iw",        "phy",     "phy0",
                            "interface", "add",     m_Monitor.c_str(),
                            "type",      "monitor", 0};
    char *const *p = const_cast<char *const *>(params);
    execv("/usr/sbin/iw", p);
    perror("execv: ");
    exit(-1);
  }
  assert(pid && "fork failed");
  int ret{99};
  wait(&ret);

  if (ret != 0) {
    SetIfaceUp(*m_PreferedIface);
    assert(1 && "iw failed");
  }

  // checks that value of Monitor is 803
  // then setChennels
  // if check failes -> stop mon abort
  if (!CheckIfaceForValue(m_Monitor, 803)) {
    std::cerr << "newly create Monitor not in Monitor mode!\n";
    std::cerr << "probably you should remove new Monitor by:\n";
    std::cerr << "iw " << m_Monitor << " del\n";
    std::cerr << "and turn on " << *m_PreferedIface << "\n";
    assert(1 && "Monitor setting fail");
  }
  sleep(1);
  // setup Monitor up
  SetIfaceUp(m_Monitor);
  // Set channel
  pid = fork();
  if (pid == 0) {
    char const *params[] = {"iw", "dev", m_Monitor.c_str(), "set", "channel",
                            "10", 0}; // 10 by default
    char *const *p = const_cast<char *const *>(params);
    execv("/usr/sbin/iw", p);
    perror("execv: ");
    exit(-1);
  }
  assert(pid && "fork failed");
  wait(&ret);

  if (ret != 0) {
    SetIfaceUp(*m_PreferedIface);
    assert(0 && "iw failed");
  }

  // Deleting iface
  pid = fork();
  if (pid == 0) {
    char const *params[] = {"iw", m_PreferedIface->c_str(), "del", 0};
    char *const *p = const_cast<char *const *>(params);
    execv("/usr/sbin/iw", p);
    perror("execv: ");
    exit(-1);
  }
  assert(pid && "fork failed");
  wait(&ret);

  if (ret != 0) {
    SetIfaceUp(*m_PreferedIface);
    assert(0 && "iw failed");
  }
}

void Monitor::TurnOff() {
  pid_t pid = fork();
  if (pid == 0) {
    char const *params[] = {"iw",        "phy",     "phy0",
                            "interface", "add",     m_PreferedIface->c_str(),
                            "type",      "station", 0};
    char *const *p = const_cast<char *const *>(params);
    execv("/usr/sbin/iw", p);
    perror("execv: ");
    exit(-1);
  }
  assert(pid && "fork failed");
  int ret{99};
  wait(&ret);

  SetIfaceDown(m_Monitor);
  // Deleting iface
  pid = fork();
  if (pid == 0) {
    char const *params[] = {"iw", m_Monitor.c_str(), "del", 0};
    char *const *p = const_cast<char *const *>(params);
    execv("/usr/sbin/iw", p);
    perror("execv: ");
    exit(-1);
  }
  assert(pid && "fork failed");
  wait(&ret);
  if (ret != 0) {
    std::cerr << "2 everything is broken!\n";
    exit(-1);
  }

  SetIfaceUp(*m_PreferedIface);
  m_IsOn = false;
}


Monitor::~Monitor() {
  sleep(1);
  if (m_IsOn)
    TurnOff();
}

char const * Monitor::GetIface() const {
  return m_Monitor.c_str();
}