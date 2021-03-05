with open("passwd.txt", 'w')as f:
    for i in range(1000000000):
        f.write(str(i)+'\n')
