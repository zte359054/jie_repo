import radius

radius.authenticate("cisco", "cisco1", "cisco", host='52.1.1.120', port=1812)

# - OR -

r = radius.Radius("cisco", host='52.1.1.120', port=1812)
print('success' if r.authenticate("cisco1", "cisco") else 'failure')