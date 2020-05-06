#!/usr/bin/env bash
#SBATCH -p wacc
#SBATCH -J attacker_block
#SBATCH -o attacker_block.out -e attacker_blcok.err
#SBATCH --gres=gpu:1 -c 1

for VAR in {2..12}
do
    command="echo '2^$VAR' | bc"
    N=$(eval $command)
    ./md5_attacker e92b330dc6a57c424cae2acacdfc8a4b $N 512 256 
done
