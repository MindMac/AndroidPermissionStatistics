'''
Created on 2014-3-8

@author: Administrator
'''

dict = {'a': 1, 'b': 4, 'c': 3, 'd':2}
sorted_x = sorted(dict.items(), key=lambda e:e[1])
print sorted_x