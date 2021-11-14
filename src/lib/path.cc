#include <path.h>
#include <cstring>
#include <cstdlib>
#include <cstdio>

path::path(char const * path_in) {
  len = strlen(path_in);
  m_path = new char[len+1];

  memcpy(m_path, path_in, len);
  m_path[len] = 0;
}

path::~path() {
  delete m_path;
}

path::path(char const * path_in, int size) {
  len = size;
  m_path = new char[len+1];
  memcpy(m_path, path_in, len);
  m_path[len] = 0;
}

path::path(path const & another) {
  len = another.len;
  m_path = new char[len+1];
  memcpy(m_path, another.m_path, len+1);
}

path path::errase_filename() const {
  char *last_slash = rindex(m_path, '/');
  if (!last_slash)
    return *this;
  
  return path(m_path, last_slash - m_path);
}

void path::print() const {
  printf("%s\n", m_path);
  fflush(NULL);
}

path & path::operator+=(path const & postfix) {
  int common_len = len + postfix.len + 1;
  char * path = new char[common_len];
  memcpy(path, m_path, len);
  path[len] = '/';
  memcpy(path + len + 1, postfix.m_path, postfix.len);
  path[common_len] = 0;
  delete m_path;
  m_path = path;
  len = common_len;
  return *this;
}

path operator+(path const & prefix, char const * postfix) {
  return path{prefix}+=path{postfix};  
}