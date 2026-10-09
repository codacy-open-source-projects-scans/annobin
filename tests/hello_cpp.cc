/*
# copyright : Copyright (c) 2026 Red Hat
# license   : GNU GFDL v1.3; see accompanying LICENSE file.
*/

extern "C" int extern_func3 (void);

class Greeter
{
public:
  int greet (void) { return extern_func3 () + 42; }
};

extern "C" int extern_func (char *, int);
extern "C" int extern_func2 (void);
extern "C" int extern_func3 (void);

extern "C" int
cpp_func (void)
{
  Greeter g;
  return g.greet ();
}

extern "C" int 
extern_func (char * array, int arg)
{
  return array[arg] * 44;
}

extern "C" int 
foo (void) 
{ 
  return 2; 
}

extern "C" int
big_stack (int arg)
{
  char array [10240];
  array[arg] = foo ();
  return extern_func (array, arg) * extern_func2 () + extern_func3 ();
}

