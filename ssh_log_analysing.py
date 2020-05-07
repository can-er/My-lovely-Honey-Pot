#!/usr/bin/env python
# coding: utf-8
"""
This program allows you to list, sort, filter and classify SSH connection attempts in a Linux system.
Author: KORKUT Caner (BE)

Don't forget to add IPs to /etc/hosts.deny: "sshd: XXX.XXX.XXX.XXX" to ban them.
"""

import os
import json

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

def count_occurence():
	ls = []
	res = log_manager(fname)
	filtered_res = dict.fromkeys(set(res[0]),0) #sans doublons
	
	for ip in filtered_res:
		for elem in res[0]:
			if ip == elem:
				filtered_res[ip] +=1
	
	for k, v in filtered_res.items():
		ls.append((k,v))
	ls.sort(key=takeSecond)
	
	
	return ls

def show_top_10(fname): 
	#On remplit une liste contenant des tuples sous la forme: [(IP,Attempts),(IP,Attempts),...]

	#On affiche le resultat
	print("Il y a eu {} tentatives de connexions SSH entre {} et {}.".format((log_manager(fname)[0]), log_manager(fname)[1][0:15],log_manager(fname)[2][0:15]))
	print("Top 10 parasites:")
	for i in range(10):
		print('{}. {}: {}'.format(i+1, count_occurence()[len(count_occurence())-i-1][0], count_occurence()[len(count_occurence())-i-1][1]))

if __name__ == "__main__":
    #On cree un fichier contenant les IP ayant rentre un mdp errone
    os.system('cat /var/log/auth.log | grep "Failed password" > parasites.txt')
    show_top_10("parasites.txt")
