#pragma once

class path {

  char * m_path{nullptr};
  int len{0};

public:
  path(char const * path_in);
  path(char const * path_in, int len);
  path(path const & another);
  ~path();
  
  path errase_filename() const;
  void print() const;

  char const * getRaw() const { return m_path; }

  path & operator+=(path const & postfix);
};

path operator+(path const & prefix, char const * postfix);