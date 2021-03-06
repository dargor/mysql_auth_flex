#ifndef AUTH_FLEX_H_
# define AUTH_FLEX_H_

struct auth_flex_data {
  void *addr_scramble, **addr_scramble_ptr;
  void *addr_rand, **addr_rand_ptr;
  void *addr_salt, **addr_salt_ptr;
  ulong client_capabilities;
};

#endif /* AUTH_FLEX_H_ */
