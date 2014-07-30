#ifndef CONFIG_H_
# define CONFIG_H_

extern int flex_debug_level;

#define INFO if (flex_debug_level >= 1)
#define DEBUG if (flex_debug_level >= 2)

#endif /* !CONFIG_H_ */
