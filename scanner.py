
from time import time
import psutil



def get_proc_list(p_list):
    #p_list={}

    for proc in psutil.process_iter(['pid', 'name','username', 'memory_full_info']):
        if (proc.info["memory_full_info"]):
            p_mem = proc.memory_full_info().data
            pid=proc.info["pid"]
            if pid in p_list.keys():
                
                p_list[pid]['prev']=p_list[pid]['curr']
                p_list[pid]['curr']=p_mem
            else:
                p_name=proc.info["name"]
                proces = {'cmd':p_name,'curr':p_mem,'prev':p_mem,'time':0 ,'count':0}
                p_list[pid]=proces
    
    return

def check_behavior(procs,stime):
    for pid,proc in procs.items():
                mem_def = abs(proc['curr'] - proc['prev'])
                if (mem_def > lower and mem_def<upper):
                    diff = (time()-stime )- proc['time'] 
                    if (diff >9 and diff<11):
                        proc['count'] +=1
                    proc['time'] += diff 

def action_for_malwares(procs,blocked_pid):
    for pid,proc in procs.items():
            if (proc['count']>2):
                print(f"process '{proc['cmd']}' detected and killed")
                blocked_pid.append(pid)
    for pid in blocked_pid:
        psutil.Process(pid).kill()
        procs.pop(pid)
        blocked_pid.remove(pid)

if __name__ == "__main__":
    lower= (200-200*0.1)*(1024*1024)
    upper= (200+200*0.1)*(1024*1024)
    blocked_proc={}
    blocked_pid=[]
    procs = {}
    print ("Scanning Processes .........\n")
    timer=time()


    while (True):
        
        # update the list with processes
        get_proc_list(procs)
        #check mem_deff and time 
        check_behavior(procs,timer)
        #take action and kill malwares
        action_for_malwares(procs,blocked_pid)
       
                    