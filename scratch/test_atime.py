import os, time

with open("test_atime.txt", "w") as f:
    f.write("hello")

stat1 = os.stat("test_atime.txt")
print("Initial atime:", stat1.st_atime)

time.sleep(1)
with open("test_atime.txt", "r") as f:
    f.read()

stat2 = os.stat("test_atime.txt")
print("After read atime:", stat2.st_atime)
print("Updated:", stat1.st_atime != stat2.st_atime)
