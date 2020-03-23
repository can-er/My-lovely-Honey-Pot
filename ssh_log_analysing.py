#!/usr/bin/env python

"""
This program allows you to list, sort, filter and classify SSH connection attempts in a Linux system.
Author: KORKUT Caner (BE)

Don't forget to add IPs to /etc/hosts.deny: "sshd: XXX.XXX.XXX.XXX" to ban them.
"""

import os
import json

#On cree un fichier contenant les IP ayant rentre un mdp errone
os.system('cat /var/log/auth.log | grep "Failed password" > parasites.txt')


def log_manager(fname):
	"""
	Traite l'entierete du fichier passe en argument.
	1) On repere le 1er et dernier
	2) On ajoute chaque IP a une liste appelee parasites[]
	3) On retourne un tuple contenant (parasites[], le 1er, le 2nd)
	"""
	with open(fname,"r") as f:
		parasites = []
		first = ""
		last = ""
		for i, l in enumerate(f):

			if len(l.split()) == 14:
				parasites.append(l.split()[10])
			elif len(l.split()) == 19:
				parasites.append(l.split()[15])
			else:
				parasites.append(l.split()[12])
			if i == 0:
				first = l
			elif i == len(parasites)-1:
				last = l
	return (parasites, first, last)


def takeSecond(elem):
	return elem[1]


def show_top_10(): 
	ls = []
	res = log_manager("parasites.txt")
	filtered_res = dict.fromkeys(set(res[0]),0) #sans doublons
	for ip in filtered_res:
		for elem in res[0]:
			if ip == elem:
				filtered_res[ip] +=1

	#On remplit une liste contenant des tuples sous la forme: [(IP,Attempts),(IP,Attempts),...]
	for k, v in filtered_res.items():
		ls.append((k,v))

	#On affiche le resultat
	print("Il y a eu {} tentatives de connexions SSH entre {} et {}.".format(len(res[0]), res[1][0:15],res[2][0:15]))
	print("Top 10 parasites:")
	ls.sort(key=takeSecond)
	for i in range(10):
		print('{}. {}: {}'.format(i+1, ls[len(ls)-i-1][0], ls[len(ls)-i-1][1]))

if __name__ == "__main__":
	show_top_10()