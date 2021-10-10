#include <monitoring.h>

#include <cassert>
#include <dirent.h>
#include <fstream>
#include <iostream>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

monitor::monitor() {
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
  CheckPreferedIface();
  SetIfaceDown();
  SetMonitor();
}

void monitor::SelectPreferedIface() {
  assert(m_Ifaces.size() && "no available interfaces.");
  for (unsigned i = 0, e = m_Ifaces.size(); i != e; ++i) {
    std::cout << i << "  " << m_Ifaces.at(i) << std::endl;
  }
  std::cout << "Select prefered interface. Enter a number.\n";
  unsigned i{0};

  std::cin >> i;
  assert(i < m_Ifaces.size() && "out of boundaries");
  m_PreferedIface = m_Ifaces.begin() + i;
}

void monitor::CheckPreferedIface() const {
  std::string fullpath = std::string{"/sys/class/ieee80211/phy0/device/net/"} +
                         *m_PreferedIface + "/type";

  std::ifstream monvalue{fullpath};
  assert(monvalue.is_open() && "cannot open file");

  int val{0};
  monvalue >> val;
  assert(val != 807 && "monitor on interface already has been established");
}

void monitor::SetIfaceDown() const { SetIface("down"); }
void monitor::SetIfaceUp() const { SetIface("up"); }

void monitor::SetIface(char const *status) const {
  pid_t pid = fork();
  if (pid == 0) {
    char const *params[] = {
        "ip", "link", "set", "dev", m_PreferedIface->c_str(), status, 0};
    char *const *p = const_cast<char *const *>(params);
    int ret = execv("/usr/bin/ip", p);
    perror("execv: ");
    assert(ret != 1 && "cannot set interface down");
  }

  assert(pid && "fork failed\n");
  int ret{99};
  wait(&ret);
}
void monitor::SetMonitor() const {}

monitor::~monitor() {
  for (auto &&x : m_Ifaces) {
    std::cout << x << "\n";
  }
  std::cout << "selected: " << *m_PreferedIface << "\n";

  SetIfaceUp();
}
