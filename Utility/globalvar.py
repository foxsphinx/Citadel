def init():
    global fun
    fun=[]
    with open('Config/DangerousFunction.txt','r') as fd:
        fun1=fd.readlines() 
    for i in fun1:  
        fun.append(i.split('\n')[0].lower())
def getFun():
    return fun