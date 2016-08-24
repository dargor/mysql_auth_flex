NAME	= auth_flex.so
RM	= rm -f

dbms		= mysql
dbms_version	?= 55
#                  55 works for mysql 5.5 and 5.6, so it's the default
#                  57 is needed for mysql 5.7

CFLAGS	= -fPIC -DMYSQL_DYNAMIC_PLUGIN -g -ggdb
LIBS	=
LDFLAGS	= -lpam

SRC	= auth_flex.c pam_flex.c auth_flex_util.c

.if $(dbms) == mysql
DBMS_CFLAGS	!= mysql_config --cflags --include | sed 's/-O2//'
DBMS_LIBS	=
SRC		+= auth_flex_dbms_mysql.c
.endif

.if $(dbms) == mariadb
DBMS_CFLAGS	!= mariadb_config --cflags --include | sed 's/-O2//'
DBMS_LIBS	=
SRC		+= auth_flex_dbms_mariadb.c
.endif

PAM_CFLAGS	=
PAM_LIBS	= -lpam

debug	=	0

CFLAGS	+= $(DBMS_CFLAGS) $(PAM_CFLAGS) -DFLEX_DEBUG_LEVEL=$(debug) -DDBMS_$(dbms)=$(dbms_version)
LIBS	+= $(DBMS_LIBS) $(PAM_LIBS)

OBJ	= $(SRC:.c=.o)

all	: $(NAME)

$(NAME)	: $(OBJ)
	cc -o $(NAME) -shared $(OBJ) $(LIBS)

install	: $(NAME)
	install $(NAME) /usr/lib/mysql/plugin/$(NAME)

clean	:
	-$(RM) $(OBJ) *~

fclean	: clean
	-$(RM) $(NAME)

re	: fclean all
