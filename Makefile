NAME	= auth_flex.so
RM	= rm -f

CFLAGS	= -fPIC -DMYSQL_DYNAMIC_PLUGIN
LIBS	=
LDFLAGS	= -lpam

MYSQL_CFLAGS	!= mysql_config --cflags --include
MYSQL_LIBS	=

PAM_CFLAGS	=
PAM_LIBS	= -lpam

debug	=	0

CFLAGS	+= $(MYSQL_CFLAGS) $(PAM_CFLAGS) -DFLEX_DEBUG_LEVEL=$(debug)
LIBS	+= $(MYSQL_LIBS) $(PAM_LIBS)

SRC	= auth_flex.c pam_flex.c
OBJ	= $(SRC:.c=.o)

all	: $(NAME)

$(NAME)	: $(OBJ)
	cc -o $(NAME) -shared $(OBJ) $(LIBS)

install	: $(NAME)
	sudo install $(NAME) /usr/lib/mysql/plugin/$(NAME)

clean	:
	-$(RM) $(OBJ) *~

fclean	: clean
	-$(RM) $(NAME)

re	: fclean all
