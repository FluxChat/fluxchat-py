
class MessageWriter():
    def __init__(self):
        print('-> __init__')

    def __enter__(self):
        print('-> __enter__')
        return 'test1'

    def __exit__(self, *args):
        print('-> __exit__')
        print(args)


mw = MessageWriter()
print(mw)

with mw as x:
    print('with mw', mw, x)

print('done')
