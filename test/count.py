f = open('bin/pathlog','r')

count = 0
for l in f:
    if len(l) == 1:
        print(count)
        count = 0
    count += 1
