#include<stdio.h>
#include<string.h>

int main(int c, char **argv)
{
    printf("%d\n",*argv[1]-'0');
    for(int i=0; i<=*argv[1]-'0';++i)
    {
        printf("%d\n",i);
    }

    return 0;
}
