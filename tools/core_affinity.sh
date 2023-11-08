#!/bin/bash

CORE_NUM=$(grep -c ^processor /proc/cpuinfo)
USED_CORES=()
TASK_SET_CMD=""

for i in $(seq 0 $CORE_NUM); do
    USED_CORES[i]=0
done

find_free_cores() {
    for FILE in /proc/[0-9]*/status; do
        # echo $FILE
        has_vm=$(cat $FILE | grep 'VmSize:')
        if [[ -z $has_vm ]]; then
            continue
        fi
        allow_list=$(cat $FILE | grep '^Cpus_allowed_list:' | awk '{print $NF}')
        # echo $allow_list
        if [[ $allow_list == *,* ]]; then
            #echo "has ,"
            continue
        fi
        if [[ $allow_list == *-* ]]; then
            # echo "has -"
            continue
        fi
        # FREE_CORES+=($allow_list)
        # echo "$allow_list is used"
        USED_CORES[$allow_list]=1
    done
}

find_core_for_task_set() {
    if [[ ! -z "${DOCKER_RUNNING:-}" ]]; then
        return
    fi
    find_free_cores
    echo "free cores: ${USED_CORES[@]}"

    for i in $(seq 0 $CORE_NUM); do
        if [ "${USED_CORES[$i]}" -eq "0" ]; then
            echo "core $i is free, set task to it"
            TASK_SET_CMD="taskset -c $i"
            break
        fi
    done
}
