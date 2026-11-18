# CTF-Pwn-Template-Code  


LOCAL=0 HOST=x PORT=y ./exp.py でリモート、GDB=1 ./exp.py で gdb を横に開きます。  
./exp.py check は保護機構と seccomp の確認だけして終わります。libc が配られていれば LIBC=./libc.so.6 を渡し、無ければリークから libc_rip({"puts": leak - base}) で引き当ててください。

fmt_payload は「書式文字列 → アラインメント → アドレス列」の順に組み、%hhn のインデックスを桁数変化込みで収束させています。  
ヌルバイトで書式が切れないので 64bit アドレスでもそのまま通ります。find_fmt_offset はオフセット自動探索ですが、問題によってはリモートでずれるので、一度ローカルで確定させて定数に埋めるほうが安全です。

brute は fork server 型（fork() するサーバ）専用です。毎回 exec し直すタイプだと 12bit でも時間がかかるので、その場合は delay を入れてください。

テンプレートのままだと exploit() の例はコメントアウトされています。
