#ifndef CONFIG_H_
# define CONFIG_H_

extern int flex_debug_level;

#define INFO if (flex_debug_level >= 1)
#define DEBUG if (flex_debug_level >= 2)

#define xstr(s) str(s)
#define str(s) #s
#define AT __FILE__ ":" xstr(__LINE__)

#endif /* !CONFIG_H_ */
