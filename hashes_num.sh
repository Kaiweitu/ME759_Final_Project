#!/usr/bin/env bash
#SBATCH -p wacc
#SBATCH -J attacker_hashes
#SBATCH -o attacker_hashes.out -e attacker_hashes.err
#SBATCH --gres=gpu:1 -c 1

for VAR in {7..17}
do
    command="echo '2^$VAR' | bc"
    N=$(eval $command)
    ./md5_attacker e92b330dc6a57c424cae2acacdfc8a4b 32 512 $N 
done
