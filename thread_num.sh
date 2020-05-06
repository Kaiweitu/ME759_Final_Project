#!/usr/bin/env bash
#SBATCH -p wacc
#SBATCH -J attacker_thread
#SBATCH -o attacker_thread.out -e attacker_thread.err
#SBATCH --gres=gpu:1 -c 1

for VAR in {8..10}
do
    command="echo '2^$VAR' | bc"
    N=$(eval $command)
    ./md5_attacker e92b330dc6a57c424cae2acacdfc8a4b 32 $N 256 
done
