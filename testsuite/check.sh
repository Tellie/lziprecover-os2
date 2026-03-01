#! /bin/sh
# check script for Lziprecover - Data recovery tool
# Copyright (C) 2009-2026 Antonio Diaz Diaz.
#
# This script is free software: you have unlimited permission
# to copy, distribute, and modify it.

LC_ALL=C
export LC_ALL
objdir=`pwd`
testdir=`cd "$1" ; pwd`
LZIP="${objdir}"/lziprecover
LZIPRECOVER="${LZIP}"
framework_failure() { echo "failure in testing framework" ; exit 1 ; }

if [ ! -f "${LZIP}" ] || [ ! -x "${LZIP}" ] ; then
	echo "${LZIP}: cannot execute"
	exit 1
fi

[ -e "${LZIP}" ] 2> /dev/null ||
	{
	echo "$0: a POSIX shell is required to run the tests"
	echo "Try bash -c \"$0 $1 $2\""
	exit 1
	}
if [ -z "${LZIP_NAME}" ] ; then LZIP_NAME=lzip ; fi
/bin/sh -c "${LZIP_NAME} --version" > /dev/null 2>&1 ||
	{ echo "$0: lzip is needed to run the tests" ; exit 1 ; }

if [ -d tmp ] ; then rm -rf tmp ; fi
mkdir tmp
cd "${objdir}"/tmp || framework_failure

cp "${testdir}"/test.txt in || framework_failure
in_lz="${testdir}"/test.txt.lz
in_lzma="${testdir}"/test.txt.lzma
inD="${testdir}"/test21636.txt
bad1_lz="${testdir}"/test_bad1.lz
bad2_lz="${testdir}"/test_bad2.lz
bad3_lz="${testdir}"/test_bad3.lz
bad4_lz="${testdir}"/test_bad4.lz
bad5_lz="${testdir}"/test_bad5.lz
bad6_lz="${testdir}"/test_bad6.lz
bad7_lz="${testdir}"/test_bad7.lz
bad8_lz="${testdir}"/test_bad8.lz
bad9_lz="${testdir}"/test_bad9.lz
fox_lz="${testdir}"/fox.lz
fnz_lz="${testdir}"/fox_nz.lz
f6b1="${testdir}"/fox6_bad1.txt
f6b1nz_lz="${testdir}"/fox6_b1nz.lz
f6b1_lz="${testdir}"/fox6_bad1.lz
f6b2_lz="${testdir}"/fox6_bad2.lz
f6b3_lz="${testdir}"/fox6_bad3.lz
f6b4_lz="${testdir}"/fox6_bad4.lz
f6b5_lz="${testdir}"/fox6_bad5.lz
f6b6_lz="${testdir}"/fox6_bad6.lz
f6s1_lz="${testdir}"/fox6_sc1.lz
f6s2_lz="${testdir}"/fox6_sc2.lz
f6s3_lz="${testdir}"/fox6_sc3.lz
f6s4_lz="${testdir}"/fox6_sc4.lz
f6s5_lz="${testdir}"/fox6_sc5.lz
f6s6_lz="${testdir}"/fox6_sc6.lz
num_lz="${testdir}"/numbers.lz
nbt_lz="${testdir}"/numbersbt.lz
fail=0
test_failed() { fail=1 ; printf " $1" ; [ -z "$2" ] || printf "($2)" ; }

# Description of test files for lziprecover:
# single-member files; test.txt.lz with one or more errors
# test_bad1.lz: byte at offset 66 changed from 0xA6 to 0x26
# test_bad2.lz: [  34-  65] --> copy of bytes [68-99]
# test_bad3.lz: [ 512-1535] --> zeroed            [2560-3583] --> zeroed
# test_bad4.lz: [3072-4095] --> random bit flips  [4608-5631] --> zeroed
# test_bad5.lz: [1024-2047] --> random bit flips  [5120-6143] --> random data
# test_bad6.lz: [ 512-1023] --> zeroed  (reference test.txt [  892- 2414])
# test_bad7.lz: [6656-7167] --> zeroed  (reference test.txt [20798-33385])
# test_bad8.lz: [  66-  73] --> zeroed  (reference test.txt [   89-  110])
# test_bad9.lz: [6491-6498] --> zeroed  (reference test.txt [17982-18594])
#
# 6-member files; fox6.lz with one or more errors
# fox6_b1nz.lz: fox6_bad1.lz with first LZMA byte set to 'a'..'f'
# fox6_bad1.lz: byte at offset   5 changed from 0x0C to 0x00 (DS)
#               byte at offset 142 changed from 0x50 to 0x70 (CRC)
#               byte at offset 224 changed from 0x2D to 0x2E (data_size)
#               byte at offset 268 changed from 0x34 to 0x33 (mid stream)
#               byte at offset 327 changed from 0x2A to 0x2B (byte 7)
#               byte at offset 458 changed from 0xA0 to 0x20 (EOS marker)
# fox6_bad2.lz: [110-129] --> zeroed  (member 2)
# fox6_bad3.lz: [180-379] --> zeroed  (members 3-5)
# fox6_bad4.lz: [330-429] --> zeroed  (members 5,6)
# fox6_bad5.lz: [380-479] --> zeroed  (members 5,6)
# fox6_bad6.lz: [430-439] --> zeroed  (member 6)
#
# 6-member files "shortcircuited" by a corrupt or fake trailer
# fox6_sc1.lz: (corrupt but consistent last trailer)
#              last CRC != 0 ; dsize = 4 * msize ; msize = 480 (file size)
# fox6_sc2.lz: (appended fake but consistent trailer)
#              fake CRC != 0 ; dsize = 4 * msize ; msize = 500 (file size)
# fox6_sc3.lz: fake CRC = 0
# fox6_sc4.lz: fake dsize = 0
# fox6_sc5.lz: fake dsize = 411 (< 8 * ( fake msize - 36 ) / 9)
# fox6_sc6.lz: fake dsize = 3360660 (>= 7090 * ( fake msize - 26 ))
#
# 9-member files "one_" "two_" "three_" "four_" "five_" "six_" "seven_"
#                "eight_" "nine_"
# numbers.lz  : good file containing the 9 members shown above
# numbersbt.lz: "gap" after "three_", "damaged" after "six_", "trailing data"

printf "testing lziprecover-%s..." "$2"

"${LZIP}" -lq in
[ $? = 2 ] || test_failed $LINENO
"${LZIP}" -tq in
[ $? = 2 ] || test_failed $LINENO
"${LZIP}" -tq < in
[ $? = 2 ] || test_failed $LINENO
"${LZIP}" -cdq in
[ $? = 2 ] || test_failed $LINENO
"${LZIP}" -cdq < in
[ $? = 2 ] || test_failed $LINENO
"${LZIP}" -dq -o in < "${in_lz}"
[ $? = 1 ] || test_failed $LINENO
"${LZIP}" -dq -o in "${in_lz}"
[ $? = 1 ] || test_failed $LINENO
"${LZIP}" -dq -o out nx_file.lz
[ $? = 1 ] || test_failed $LINENO
[ ! -e out ] || test_failed $LINENO
# these are for code coverage
"${LZIP}" -lt "${in_lz}" 2> /dev/null
[ $? = 1 ] || test_failed $LINENO
"${LZIP}" -cdl "${in_lz}" 2> /dev/null
[ $? = 1 ] || test_failed $LINENO
"${LZIP}" -cdt "${in_lz}" 2> /dev/null
[ $? = 1 ] || test_failed $LINENO
"${LZIP}" -t -- nx_file.lz 2> /dev/null
[ $? = 1 ] || test_failed $LINENO
"${LZIP}" -t "" < /dev/null 2> /dev/null
[ $? = 1 ] || test_failed $LINENO
"${LZIP}" --help > /dev/null || test_failed $LINENO
"${LZIP}" -n1 -V > /dev/null || test_failed $LINENO
"${LZIP}" -m 2> /dev/null
[ $? = 1 ] || test_failed $LINENO
"${LZIP}" -z 2> /dev/null
[ $? = 1 ] || test_failed $LINENO
"${LZIP}" --bad_option 2> /dev/null
[ $? = 1 ] || test_failed $LINENO
"${LZIP}" --t 2> /dev/null
[ $? = 1 ] || test_failed $LINENO
"${LZIP}" --test=2 2> /dev/null
[ $? = 1 ] || test_failed $LINENO
"${LZIP}" --output= 2> /dev/null
[ $? = 1 ] || test_failed $LINENO
"${LZIP}" --output 2> /dev/null
[ $? = 1 ] || test_failed $LINENO
printf "LZIP\001-.............................." | "${LZIP}" -t 2> /dev/null
printf "LZIP\002-.............................." | "${LZIP}" -t 2> /dev/null
printf "LZIP\001+.............................." | "${LZIP}" -t 2> /dev/null

"${LZIPRECOVER}" -q --nrep-stats=0N "${in_lz}"
[ $? = 1 ] || test_failed $LINENO
for i in 0 0_000_000k 0x40 0300 255 0kB 0KiB 0M 0G 0T 0P 0E 0Z 0Y 0R 0Q ; do
	"${LZIPRECOVER}" --nrep-stats=$i "${in_lz}" > /dev/null ||
	  test_failed $LINENO $i
done
"${LZIPRECOVER}" -eq "${bad6_lz}"
[ $? = 1 ] || test_failed $LINENO
"${LZIPRECOVER}" -mq "${bad1_lz}"
[ $? = 1 ] || test_failed $LINENO
"${LZIPRECOVER}" -Bq
[ $? = 1 ] || test_failed $LINENO
"${LZIPRECOVER}" -sq
[ $? = 1 ] || test_failed $LINENO
"${LZIPRECOVER}" -t --remove=damaged "${in_lz}" 2> /dev/null
[ $? = 1 ] || test_failed $LINENO
"${LZIPRECOVER}" --strip=damaged -t "${in_lz}" 2> /dev/null
[ $? = 1 ] || test_failed $LINENO
"${LZIPRECOVER}" --remove=tdata -t "${in_lz}" 2> /dev/null
[ $? = 1 ] || test_failed $LINENO
"${LZIPRECOVER}" -t --strip=tdata "${in_lz}" 2> /dev/null
[ $? = 1 ] || test_failed $LINENO
"${LZIPRECOVER}" -q --dump=tdata --strip=damaged "${in_lz}"
[ $? = 1 ] || test_failed $LINENO
"${LZIPRECOVER}" --remove=tdata --strip=damaged "${in_lz}" 2> /dev/null
[ $? = 1 ] || test_failed $LINENO
"${LZIPRECOVER}" -q --dump=damaged
[ $? = 1 ] || test_failed $LINENO
"${LZIPRECOVER}" -q --dump=damaged in > out	# /dev/null returns 1 on OS/2
[ $? = 2 ] || test_failed $LINENO
"${LZIPRECOVER}" -q --dump=damageed "${in_lz}" > /dev/null
[ $? = 1 ] || test_failed $LINENO
"${LZIPRECOVER}" -q --dump=empty
[ $? = 1 ] || test_failed $LINENO
"${LZIPRECOVER}" -q --strip=damaged
[ $? = 1 ] || test_failed $LINENO
"${LZIPRECOVER}" -q --strip=damaged in > out	# /dev/null returns 1 on OS/2
[ $? = 2 ] || test_failed $LINENO
"${LZIPRECOVER}" -q --strip=damageed "${in_lz}" > /dev/null
[ $? = 1 ] || test_failed $LINENO
"${LZIPRECOVER}" -q --remove=damaged
[ $? = 1 ] || test_failed $LINENO
"${LZIPRECOVER}" -q --remove=damaged in
[ $? = 2 ] || test_failed $LINENO
"${LZIPRECOVER}" -q --remove=damageed "${in_lz}"
[ $? = 1 ] || test_failed $LINENO
"${LZIPRECOVER}" -q --dump=tdata
[ $? = 1 ] || test_failed $LINENO
"${LZIPRECOVER}" -q --dump=tdata in > /dev/null
[ $? = 2 ] || test_failed $LINENO
"${LZIPRECOVER}" -q --dump=tdataa "${in_lz}" > /dev/null
[ $? = 1 ] || test_failed $LINENO
"${LZIPRECOVER}" -q --strip=tdata
[ $? = 1 ] || test_failed $LINENO
"${LZIPRECOVER}" -q --strip=tdata in > out	# /dev/null returns 1 on OS/2
[ $? = 2 ] || test_failed $LINENO
"${LZIPRECOVER}" -q --strip=tdataa "${in_lz}" > /dev/null
[ $? = 1 ] || test_failed $LINENO
"${LZIPRECOVER}" -q --remove=tdata
[ $? = 1 ] || test_failed $LINENO
"${LZIPRECOVER}" -q --remove=tdata in
[ $? = 2 ] || test_failed $LINENO
"${LZIPRECOVER}" -q --remove=tdataa "${in_lz}"
[ $? = 1 ] || test_failed $LINENO

"${LZIPRECOVER}" -Aq in
[ $? = 2 ] || test_failed $LINENO
"${LZIPRECOVER}" -Aq < in > out		# /dev/null returns 1 on OS/2
[ $? = 2 ] || test_failed $LINENO
"${LZIPRECOVER}" -Aq < "${in_lz}" > out
[ $? = 2 ] || test_failed $LINENO
"${LZIPRECOVER}" -Aq "${in_lz}"
[ $? = 1 ] || test_failed $LINENO
"${LZIPRECOVER}" -Akq "${in_lzma}"
[ $? = 1 ] || test_failed $LINENO
rm -f out || framework_failure
"${LZIPRECOVER}" -A "${in_lzma}" -o out.lz || test_failed $LINENO
cmp "${in_lz}" out.lz || test_failed $LINENO
"${LZIPRECOVER}" -Ac "${in_lzma}" > out.lz || test_failed $LINENO
cmp "${in_lz}" out.lz || test_failed $LINENO
rm -f out.lz || framework_failure
"${LZIPRECOVER}" -A -o out.lz < "${in_lzma}" || test_failed $LINENO
cmp "${in_lz}" out.lz || test_failed $LINENO
"${LZIPRECOVER}" -A < "${in_lzma}" > out.lz || test_failed $LINENO
cmp "${in_lz}" out.lz || test_failed $LINENO
rm -f out.lz || framework_failure
cp "${in_lzma}" out.lzma || framework_failure
"${LZIPRECOVER}" -Ak out.lzma || test_failed $LINENO
cmp "${in_lz}" out.lz || test_failed $LINENO
printf "to be overwritten" > out.lz || framework_failure
"${LZIPRECOVER}" -Af out.lzma || test_failed $LINENO
[ ! -e out.lzma ] || test_failed $LINENO
cmp "${in_lz}" out.lz || test_failed $LINENO
rm -f out.lz || framework_failure
cp "${in_lzma}" out.tlz || framework_failure
"${LZIPRECOVER}" -Ak out.tlz || test_failed $LINENO
cmp "${in_lz}" out.tar.lz || test_failed $LINENO
printf "to be overwritten" > out.tar.lz || framework_failure
"${LZIPRECOVER}" -Af out.tlz || test_failed $LINENO
cmp "${in_lz}" out.tar.lz || test_failed $LINENO
rm -f out.tar.lz || framework_failure
cat in in > in2 || framework_failure
"${LZIPRECOVER}" -A -o out2.lz - "${in_lzma}" - < "${in_lzma}" ||
	test_failed $LINENO
"${LZIP}" -d out2.lz || test_failed $LINENO
cmp in2 out2 || test_failed $LINENO
rm -f out2 || framework_failure
"${LZIPRECOVER}" -A "${in_lzma}" -o a/b/c/out.lz || test_failed $LINENO
cmp "${in_lz}" a/b/c/out.lz || test_failed $LINENO
rm -rf a || framework_failure

printf "\ntesting decompression..."

"${LZIP}" -l "${in_lz}" > /dev/null || test_failed $LINENO
"${LZIP}" -t "${in_lz}" || test_failed $LINENO
"${LZIP}" -d "${in_lz}" -o out || test_failed $LINENO
cmp in out || test_failed $LINENO
"${LZIP}" -cd "${in_lz}" > out || test_failed $LINENO
cmp in out || test_failed $LINENO
"${LZIP}" -d "${in_lz}" -o - > out || test_failed $LINENO
cmp in out || test_failed $LINENO
"${LZIP}" -d < "${in_lz}" > out || test_failed $LINENO
cmp in out || test_failed $LINENO
rm -f out || framework_failure

cp "${in_lz}" out.lz || framework_failure
"${LZIP}" -dk out.lz || test_failed $LINENO
cmp in out || test_failed $LINENO
rm -f out || framework_failure
"${LZIP}" -cd "${fox_lz}" > fox || test_failed $LINENO
cp fox copy || framework_failure
cp "${in_lz}" copy.lz || framework_failure
"${LZIP}" -d copy.lz out.lz 2> /dev/null	# skip copy, decompress out
[ $? = 1 ] || test_failed $LINENO
[ ! -e out.lz ] || test_failed $LINENO
cmp fox copy || test_failed $LINENO
cmp in out || test_failed $LINENO
"${LZIP}" -df copy.lz || test_failed $LINENO
[ ! -e copy.lz ] || test_failed $LINENO
cmp in copy || test_failed $LINENO
rm -f copy out || framework_failure

printf "to be overwritten" > out || framework_failure
"${LZIP}" -df -o out < "${in_lz}" || test_failed $LINENO
cmp in out || test_failed $LINENO
"${LZIP}" -d -o ./- "${in_lz}" || test_failed $LINENO
cmp in ./- || test_failed $LINENO
rm -f ./- || framework_failure
"${LZIP}" -d -o ./- < "${in_lz}" || test_failed $LINENO
cmp in ./- || test_failed $LINENO
rm -f ./- || framework_failure

cp "${in_lz}" anyothername || framework_failure
"${LZIP}" -dv - anyothername - < "${in_lz}" > out 2> /dev/null ||
	test_failed $LINENO
cmp in out || test_failed $LINENO
cmp in anyothername.out || test_failed $LINENO
rm -f anyothername.out || framework_failure

"${LZIP}" -lq in "${in_lz}"
[ $? = 2 ] || test_failed $LINENO
"${LZIP}" -lq nx_file.lz "${in_lz}"
[ $? = 1 ] || test_failed $LINENO
"${LZIP}" -tq in "${in_lz}"
[ $? = 2 ] || test_failed $LINENO
"${LZIP}" -tq nx_file.lz "${in_lz}"
[ $? = 1 ] || test_failed $LINENO
"${LZIP}" -cdq in "${in_lz}" > out
[ $? = 2 ] || test_failed $LINENO
cat out in | cmp in - || test_failed $LINENO		# out must be empty
"${LZIP}" -cdq nx_file.lz "${in_lz}" > out	# skip nx_file, decompress in
[ $? = 1 ] || test_failed $LINENO
cmp in out || test_failed $LINENO
rm -f out || framework_failure
cp "${in_lz}" out.lz || framework_failure
for i in 1 2 3 4 5 6 7 ; do
	printf "g" >> out.lz || framework_failure
	"${LZIP}" -alvv out.lz "${in_lz}" > /dev/null 2>&1
	[ $? = 2 ] || test_failed $LINENO $i
	"${LZIP}" -atvvvv out.lz "${in_lz}" 2> /dev/null
	[ $? = 2 ] || test_failed $LINENO $i
done
"${LZIP}" -dq in out.lz
[ $? = 2 ] || test_failed $LINENO
[ -e out.lz ] || test_failed $LINENO
[ ! -e out ] || test_failed $LINENO
[ ! -e in.out ] || test_failed $LINENO
"${LZIP}" -dq nx_file.lz out.lz
[ $? = 1 ] || test_failed $LINENO
[ ! -e out.lz ] || test_failed $LINENO
[ ! -e nx_file ] || test_failed $LINENO
cmp in out || test_failed $LINENO
rm -f out || framework_failure

"${LZIP}" -l "${in_lz}" "${in_lz}" > /dev/null || test_failed $LINENO
"${LZIP}" -t "${in_lz}" "${in_lz}" || test_failed $LINENO
"${LZIP}" -cd "${in_lz}" "${in_lz}" -o out > out2 || test_failed $LINENO
[ ! -e out ] || test_failed $LINENO			# override -o
cmp in2 out2 || test_failed $LINENO
rm -f out2 || framework_failure
"${LZIP}" -d "${in_lz}" "${in_lz}" -o out2 || test_failed $LINENO
cmp in2 out2 || test_failed $LINENO
rm -f out2 || framework_failure

cat "${in_lz}" "${in_lz}" > out2.lz || framework_failure
lines=`"${LZIP}" -tvv out2.lz 2>&1 | wc -l` || test_failed $LINENO
[ "${lines}" -eq 2 ] || test_failed $LINENO "${lines}"
lines=`"${LZIP}" -lvv out2.lz | wc -l` || test_failed $LINENO
[ "${lines}" -eq 5 ] || test_failed $LINENO "${lines}"

printf "\ngarbage" >> out2.lz || framework_failure
"${LZIP}" -tvvvv out2.lz 2> /dev/null || test_failed $LINENO
"${LZIP}" -alq out2.lz
[ $? = 2 ] || test_failed $LINENO
"${LZIP}" -atq out2.lz
[ $? = 2 ] || test_failed $LINENO
"${LZIP}" -atq < out2.lz
[ $? = 2 ] || test_failed $LINENO
"${LZIP}" -adkq out2.lz
[ $? = 2 ] || test_failed $LINENO
[ ! -e out2 ] || test_failed $LINENO
"${LZIP}" -adkq -o out2 < out2.lz
[ $? = 2 ] || test_failed $LINENO
[ ! -e out2 ] || test_failed $LINENO
"${LZIPRECOVER}" -aD0 -q out2.lz
[ $? = 2 ] || test_failed $LINENO
printf "to be overwritten" > out2 || framework_failure
"${LZIP}" -df out2.lz || test_failed $LINENO
cmp in2 out2 || test_failed $LINENO
rm -f out2 || framework_failure

"${LZIP}" -d "${fox_lz}" -o a/b/c/fox || test_failed $LINENO
cmp fox a/b/c/fox || test_failed $LINENO
rm -rf a || framework_failure
"${LZIP}" -d -o a/b/c/fox < "${fox_lz}" || test_failed $LINENO
cmp fox a/b/c/fox || test_failed $LINENO
rm -rf a || framework_failure
"${LZIP}" -dq "${fox_lz}" -o a/b/c/
[ $? = 1 ] || test_failed $LINENO
[ ! -e a ] || test_failed $LINENO

touch empty em || framework_failure
"${LZIP_NAME}" -0 em || test_failed $LINENO
"${LZIP}" -l em.lz > /dev/null || test_failed $LINENO
"${LZIP}" -dk em.lz || test_failed $LINENO
cmp empty em || test_failed $LINENO
cat em.lz em.lz | "${LZIP}" -t || test_failed $LINENO
cat em.lz em.lz | "${LZIP}" -d > em || test_failed $LINENO
cmp empty em || test_failed $LINENO
cat em.lz "${in_lz}" | "${LZIP}" -t || test_failed $LINENO
cat em.lz "${in_lz}" | "${LZIP}" -d > out || test_failed $LINENO
cmp in out || test_failed $LINENO
cat "${in_lz}" em.lz | "${LZIP}" -t || test_failed $LINENO
cat "${in_lz}" em.lz | "${LZIP}" -d > out || test_failed $LINENO
cmp in out || test_failed $LINENO

cat em.lz "${fox_lz}" em.lz "${fox_lz}" em.lz em.lz "${fox_lz}" em.lz > \
    f3_em.lz || framework_failure
"${LZIPRECOVER}" -D ,18000 "${in_lz}" > out || test_failed $LINENO
"${LZIPRECOVER}" -D 18_000 "${in_lz}" >> out || test_failed $LINENO
cmp in out || test_failed $LINENO
"${LZIPRECOVER}" -D 21636-22033 -fo out "${in_lz}" || test_failed $LINENO
cmp "${inD}" out || test_failed $LINENO
"${LZIPRECOVER}" -D 21636,397 "${in_lz}" > out || test_failed $LINENO
cmp "${inD}" out || test_failed $LINENO
"${LZIPRECOVER}" -D 45,45 f3_em.lz > out || test_failed $LINENO
cmp fox out || test_failed $LINENO
"${LZIP}" -D 0 "${in_lz}" -o a/b/c/out || test_failed $LINENO
cmp in a/b/c/out || test_failed $LINENO
rm -rf a || framework_failure

printf "\ntesting bad input..."

cat em.lz em.lz > ee.lz || framework_failure
"${LZIP}" -l < ee.lz > /dev/null || test_failed $LINENO
"${LZIP}" -t < ee.lz || test_failed $LINENO
"${LZIP}" -d < ee.lz > em || test_failed $LINENO
cmp empty em || test_failed $LINENO
"${LZIPRECOVER}" -li ee.lz > /dev/null || test_failed $LINENO
"${LZIPRECOVER}" -ti ee.lz || test_failed $LINENO
"${LZIPRECOVER}" -cdi ee.lz > em || test_failed $LINENO
cmp empty em || test_failed $LINENO
"${LZIP}" -lq ee.lz
[ $? = 2 ] || test_failed $LINENO
"${LZIP}" -tq ee.lz
[ $? = 2 ] || test_failed $LINENO
"${LZIP}" -dq ee.lz
[ $? = 2 ] || test_failed $LINENO
[ ! -e ee ] || test_failed $LINENO
"${LZIP}" -cdq ee.lz > em
[ $? = 2 ] || test_failed $LINENO
cmp empty em || test_failed $LINENO
rm -f em || framework_failure
cat "${in_lz}" em.lz "${in_lz}" > inein.lz || framework_failure
"${LZIP}" -l < inein.lz > /dev/null || test_failed $LINENO
"${LZIP}" -t < inein.lz || test_failed $LINENO
"${LZIP}" -d < inein.lz > out2 || test_failed $LINENO
cmp in2 out2 || test_failed $LINENO
"${LZIPRECOVER}" -li inein.lz > /dev/null || test_failed $LINENO
"${LZIPRECOVER}" -ti inein.lz || test_failed $LINENO
"${LZIPRECOVER}" -cdi inein.lz > out2 || test_failed $LINENO
cmp in2 out2 || test_failed $LINENO
"${LZIP}" -lq inein.lz
[ $? = 2 ] || test_failed $LINENO
"${LZIP}" -tq inein.lz
[ $? = 2 ] || test_failed $LINENO
"${LZIP}" -dq inein.lz
[ $? = 2 ] || test_failed $LINENO
[ ! -e inein ] || test_failed $LINENO
"${LZIP}" -cdq inein.lz > out2
[ $? = 2 ] || test_failed $LINENO
cmp in2 out2 || test_failed $LINENO
rm -f out2 inein.lz em.lz || framework_failure

headers='LZIp LZiP LZip LzIP LzIp LziP lZIP lZIp lZiP lzIP'
body='\001\014\000\000\101\376\367\377\377\340\000\200\000\215\357\002\322\001\000\000\000\000\000\000\000\045\000\000\000\000\000\000\000'
cp "${in_lz}" int.lz || framework_failure
printf "LZIP${body}" >> int.lz || framework_failure
if "${LZIP}" -t int.lz ; then
	for header in ${headers} ; do
		printf "${header}${body}" > int.lz || framework_failure
		"${LZIP}" -lq int.lz			# first member
		[ $? = 2 ] || test_failed $LINENO ${header}
		"${LZIP}" -tq int.lz
		[ $? = 2 ] || test_failed $LINENO ${header}
		"${LZIP}" -tq < int.lz
		[ $? = 2 ] || test_failed $LINENO ${header}
		"${LZIP}" -cdq int.lz > /dev/null
		[ $? = 2 ] || test_failed $LINENO ${header}
		"${LZIP}" -lq --loose-trailing int.lz
		[ $? = 2 ] || test_failed $LINENO ${header}
		"${LZIP}" -tq --loose-trailing int.lz
		[ $? = 2 ] || test_failed $LINENO ${header}
		"${LZIP}" -tq --loose-trailing < int.lz
		[ $? = 2 ] || test_failed $LINENO ${header}
		"${LZIP}" -cdq --loose-trailing int.lz > /dev/null
		[ $? = 2 ] || test_failed $LINENO ${header}
		cp "${in_lz}" int.lz || framework_failure
		printf "${header}${body}" >> int.lz || framework_failure
		"${LZIP}" -lq int.lz			# trailing data
		[ $? = 2 ] || test_failed $LINENO ${header}
		"${LZIP}" -tq int.lz
		[ $? = 2 ] || test_failed $LINENO ${header}
		"${LZIP}" -tq < int.lz
		[ $? = 2 ] || test_failed $LINENO ${header}
		"${LZIP}" -cdq int.lz > /dev/null
		[ $? = 2 ] || test_failed $LINENO ${header}
		"${LZIP}" -l --loose-trailing int.lz > /dev/null ||
			test_failed $LINENO ${header}
		"${LZIP}" -t --loose-trailing int.lz ||
			test_failed $LINENO ${header}
		"${LZIP}" -t --loose-trailing < int.lz ||
			test_failed $LINENO ${header}
		"${LZIP}" -cd --loose-trailing int.lz > /dev/null ||
			test_failed $LINENO ${header}
		"${LZIP}" -lq --loose-trailing --trailing-error int.lz
		[ $? = 2 ] || test_failed $LINENO ${header}
		"${LZIP}" -tq --loose-trailing --trailing-error int.lz
		[ $? = 2 ] || test_failed $LINENO ${header}
		"${LZIP}" -tq --loose-trailing --trailing-error < int.lz
		[ $? = 2 ] || test_failed $LINENO ${header}
		"${LZIP}" -cdq --loose-trailing --trailing-error int.lz > /dev/null
		[ $? = 2 ] || test_failed $LINENO ${header}
		"${LZIPRECOVER}" -q --dump=tdata int.lz > /dev/null
		[ $? = 2 ] || test_failed $LINENO ${header}
		"${LZIPRECOVER}" -q --strip=tdata int.lz > out	# /dev/null returns 1 on OS/2
		[ $? = 2 ] || test_failed $LINENO ${header}
		"${LZIPRECOVER}" --dump=tdata --loose-trailing int.lz > \
			/dev/null || test_failed $LINENO ${header}
		"${LZIPRECOVER}" --strip=tdata --loose-trailing int.lz > \
			out || test_failed $LINENO ${header}
		"${LZIPRECOVER}" -q --remove=tdata int.lz
		[ $? = 2 ] || test_failed $LINENO ${header}
		"${LZIPRECOVER}" --remove=tdata --loose-trailing int.lz ||
			test_failed $LINENO ${header}
		cmp "${in_lz}" int.lz || test_failed $LINENO ${header}
	done
else
	printf "warning: skipping header test: 'printf' does not work on your system."
fi
rm -f int.lz || framework_failure

"${LZIP}" -l "${fnz_lz}" > /dev/null || test_failed $LINENO
"${LZIP}" -tq "${fnz_lz}"
[ $? = 2 ] || test_failed $LINENO
cat "${fox_lz}" "${fox_lz}" "${fox_lz}" "${fox_lz}" "${fox_lz}" "${fox_lz}" \
    > fox6.lz || framework_failure
cat "${fox_lz}" "${fnz_lz}" "${fox_lz}" "${fnz_lz}" "${fox_lz}" "${fnz_lz}" \
    > fox6_nz.lz || framework_failure
"${LZIP}" -cd fox6.lz > out || test_failed $LINENO
"${LZIPRECOVER}" -cd -i fox6_nz.lz > copy || test_failed $LINENO
cmp copy out || test_failed $LINENO
rm -f copy || framework_failure
cp fox6_nz.lz f6nz.lz || framework_failure
cp fox6_nz.lz f6nz2.lz || framework_failure
cp "${f6b1nz_lz}" f6b1nz.lz || framework_failure
cmp -s fox6.lz f6nz.lz && test_failed $LINENO
"${LZIPRECOVER}" --nonzero-repair f6nz.lz f6nz2.lz f6b1nz.lz ||
	test_failed $LINENO
cmp fox6.lz f6nz.lz || test_failed $LINENO
cmp fox6.lz f6nz2.lz || test_failed $LINENO
cmp "${f6b1_lz}" f6b1nz.lz || test_failed $LINENO
rm -f f6nz.lz f6nz2.lz f6b1nz.lz || framework_failure

for i in fox_v2.lz fox_s11.lz fox_de20.lz \
         fox_bcrc.lz fox_crc0.lz fox_das46.lz fox_mes81.lz ; do
	"${LZIP}" -tq "${testdir}"/$i
	[ $? = 2 ] || test_failed $LINENO $i
done

for i in fox_bcrc.lz fox_crc0.lz fox_das46.lz fox_mes81.lz ; do
	"${LZIP}" -cdq "${testdir}"/$i > out
	[ $? = 2 ] || test_failed $LINENO $i
	cmp fox out || test_failed $LINENO $i
	"${LZIPRECOVER}" -tq -i "${testdir}"/$i || test_failed $LINENO $i
	"${LZIPRECOVER}" -cdq -i "${testdir}"/$i > out || test_failed $LINENO $i
	cmp fox out || test_failed $LINENO $i
done
rm -f fox || framework_failure

cat "${in_lz}" "${in_lz}" > in2.lz || framework_failure
cat "${in_lz}" "${in_lz}" "${in_lz}" > in3.lz || framework_failure
if dd if=in3.lz of=trunc.lz bs=14682 count=1 2> /dev/null &&
   [ -e trunc.lz ] && cmp in2.lz trunc.lz ; then
	for i in 6 20 14664 14683 14684 14685 14686 14687 14688 ; do
		dd if=in3.lz of=trunc.lz bs=$i count=1 2> /dev/null
		"${LZIP}" -lq trunc.lz
		[ $? = 2 ] || test_failed $LINENO $i
		"${LZIP}" -tq trunc.lz
		[ $? = 2 ] || test_failed $LINENO $i
		"${LZIP}" -tq < trunc.lz
		[ $? = 2 ] || test_failed $LINENO $i
		"${LZIP}" -cdq trunc.lz > /dev/null
		[ $? = 2 ] || test_failed $LINENO $i
		"${LZIP}" -dq < trunc.lz > /dev/null
		[ $? = 2 ] || test_failed $LINENO $i
	done
else
	printf "warning: skipping truncation test: 'dd' does not work on your system."
fi
rm -f in3.lz trunc.lz || framework_failure

for i in "${f6s1_lz}" "${f6s2_lz}" ; do
	lines=`"${LZIP}" -lvv "$i" | wc -l || test_failed $LINENO "$i"`
	[ "${lines}" -eq 2 ] || test_failed $LINENO "$i ${lines}"
done
for i in "${f6s3_lz}" "${f6s4_lz}" "${f6s5_lz}" "${f6s6_lz}" ; do
	lines=`"${LZIP}" -lvv "$i" | wc -l || test_failed $LINENO "$i"`
	[ "${lines}" -eq 10 ] || test_failed $LINENO "$i ${lines}"
done

cp "${in_lz}" ingin.lz || framework_failure
printf "g" >> ingin.lz || framework_failure
cat "${in_lz}" >> ingin.lz || framework_failure
"${LZIP}" -lq ingin.lz
[ $? = 2 ] || test_failed $LINENO
"${LZIP}" -atq ingin.lz
[ $? = 2 ] || test_failed $LINENO
"${LZIP}" -atq < ingin.lz
[ $? = 2 ] || test_failed $LINENO
"${LZIP}" -acdq ingin.lz > out
[ $? = 2 ] || test_failed $LINENO
cmp in out || test_failed $LINENO
"${LZIP}" -adq < ingin.lz > out
[ $? = 2 ] || test_failed $LINENO
cmp in out || test_failed $LINENO
"${LZIP}" -t ingin.lz || test_failed $LINENO
"${LZIP}" -t < ingin.lz || test_failed $LINENO
"${LZIP}" -dk ingin.lz || test_failed $LINENO
cmp in ingin || test_failed $LINENO
"${LZIP}" -cd ingin.lz > out || test_failed $LINENO
cmp in out || test_failed $LINENO
"${LZIP}" -d < ingin.lz > out || test_failed $LINENO
cmp in out || test_failed $LINENO
rm -f ingin || framework_failure
"${LZIPRECOVER}" -l -i ingin.lz > /dev/null || test_failed $LINENO
"${LZIPRECOVER}" -cd -i ingin.lz > out2 || test_failed $LINENO
cmp in2 out2 || test_failed $LINENO

"${LZIPRECOVER}" -D0 -q "${f6b1_lz}" -fo out
[ $? = 2 ] || test_failed $LINENO
cmp -s "${f6b1}" out && test_failed $LINENO
"${LZIPRECOVER}" -D0 -q "${f6b1_lz}" > out
[ $? = 2 ] || test_failed $LINENO
cmp -s "${f6b1}" out && test_failed $LINENO
"${LZIPRECOVER}" -D0 -iq "${f6b1_lz}" -fo out || test_failed $LINENO
cmp "${f6b1}" out || test_failed $LINENO
"${LZIPRECOVER}" -D0 -iq "${f6b1_lz}" > out || test_failed $LINENO
cmp "${f6b1}" out || test_failed $LINENO

"${LZIPRECOVER}" -D0 -q ingin.lz > out
[ $? = 2 ] || test_failed $LINENO
cmp empty out || test_failed $LINENO
"${LZIPRECOVER}" -D0 -i ingin.lz > out2 || test_failed $LINENO
cmp in2 out2 || test_failed $LINENO
printf "LZIP\001+" > in2t.lz || framework_failure	# gap size < 36 bytes
cat "${in_lz}" in "${in_lz}" >> in2t.lz || framework_failure
printf "LZIP\001-" >> in2t.lz || framework_failure	# truncated member
"${LZIPRECOVER}" -D0 -iq in2t.lz > out2 || test_failed $LINENO
cmp in2 out2 || test_failed $LINENO
"${LZIPRECOVER}" -cd -iq in2t.lz > out2 || test_failed $LINENO
cmp in2 out2 || test_failed $LINENO
"${LZIPRECOVER}" -t -iq in2t.lz || test_failed $LINENO
rm -f in2 in2t.lz out out2 || framework_failure

printf "\ntesting --byte-repair..."

rm -f out.lz || framework_failure
"${LZIPRECOVER}" -B -o out.lz fox6.lz || test_failed $LINENO
[ ! -e out.lz ] || test_failed $LINENO
"${LZIPRECOVER}" -B -o out.lz "${bad2_lz}" -q
[ $? = 2 ] || test_failed $LINENO
[ ! -e out.lz ] || test_failed $LINENO
"${LZIPRECOVER}" -B -o out.lz "${bad3_lz}" -q
[ $? = 2 ] || test_failed $LINENO
[ ! -e out.lz ] || test_failed $LINENO
"${LZIPRECOVER}" -B -o out.lz "${bad4_lz}" -q
[ $? = 2 ] || test_failed $LINENO
[ ! -e out.lz ] || test_failed $LINENO
"${LZIPRECOVER}" -Bf -o out.lz "${f6b1_lz}" || test_failed $LINENO
cmp fox6.lz out.lz || test_failed $LINENO
"${LZIPRECOVER}" -Bf fox6_nz.lz -o out.lz || test_failed $LINENO
cmp fox6.lz out.lz || test_failed $LINENO
"${LZIPRECOVER}" -Bf "${f6b1nz_lz}" -o out.lz || test_failed $LINENO
cmp fox6.lz out.lz || test_failed $LINENO
"${LZIPRECOVER}" -Bf -o out.lz "${bad1_lz}" || test_failed $LINENO
cmp "${in_lz}" out.lz || test_failed $LINENO
"${LZIPRECOVER}" -B -o a/b/c/out.lz "${bad1_lz}" || test_failed $LINENO
cmp "${in_lz}" a/b/c/out.lz || test_failed $LINENO
rm -rf a || framework_failure

cp "${f6b1_lz}" out.lz || framework_failure
"${LZIPRECOVER}" -B out.lz || test_failed $LINENO
[ -e out_fixed.lz ] || test_failed $LINENO
mv out.lz out.tar.lz || framework_failure
"${LZIPRECOVER}" -B out.tar.lz || test_failed $LINENO
[ -e out_fixed.tar.lz ] || test_failed $LINENO
mv out.tar.lz out.tlz || framework_failure
"${LZIPRECOVER}" -B out.tlz || test_failed $LINENO
[ -e out_fixed.tlz ] || test_failed $LINENO
rm -f out.tlz out_fixed.lz out_fixed.tar.lz out_fixed.tlz ||
	framework_failure

printf "\ntesting --fec..."

"${LZIPRECOVER}" -q -Ft -r . --fec-file="${in_lz}".fec
[ $? = 1 ] || test_failed $LINENO
"${LZIPRECOVER}" -q -Ft -r "${in_lz}" --fec-file="${in_lz}".fec
[ $? = 1 ] || test_failed $LINENO
"${LZIPRECOVER}" -Ft "${in_lz}" || test_failed $LINENO
"${LZIPRECOVER}" -Fc "${in_lz}" -o fecfile.fec || test_failed $LINENO
cmp "${in_lz}".fec fecfile.fec || test_failed $LINENO
"${LZIPRECOVER}" -Fc -cn1 "${in_lz}" | cmp fecfile.fec - || test_failed $LINENO
"${LZIPRECOVER}" -Fc -cn4 "${in_lz}" | cmp fecfile.fec - || test_failed $LINENO
"${LZIPRECOVER}" -Fc -c --gf16 "${in_lz}" | cmp "${in_lz}".fec16 - ||
	test_failed $LINENO

cp "${in_lz}" in.lz || framework_failure
"${LZIPRECOVER}" --append=in in.lz || test_failed $LINENO
cat "${in_lz}" in | cmp in.lz - || test_failed $LINENO
"${LZIP}" -cd in.lz | cmp in - || test_failed $LINENO
"${LZIPRECOVER}" --dump=tdata in.lz | cmp in - || test_failed $LINENO
cp "${in_lz}" in.lz || framework_failure
"${LZIPRECOVER}" --append="${fox_lz}" in.lz || test_failed $LINENO
cat "${in_lz}" "${fox_lz}" | cmp -s in.lz - && test_failed $LINENO
"${LZIP}" -cd in.lz | cmp in - || test_failed $LINENO
"${LZIPRECOVER}" --dump=tdata in.lz | cmp "${fox_lz}" - || test_failed $LINENO

cp "${in_lz}" in.lz || framework_failure
"${LZIPRECOVER}" -Fc -c in.lz | "${LZIPRECOVER}" --append=- in.lz ||
	test_failed $LINENO
cat "${in_lz}" fecfile.fec | cmp -s in.lz - && test_failed $LINENO
"${LZIPRECOVER}" --dump=tdata in.lz | cmp fecfile.fec - || test_failed $LINENO
"${LZIPRECOVER}" --dump=tdata in.lz | "${LZIPRECOVER}" -q -Ft --fec-file=- \
	in.lz || test_failed $LINENO
"${LZIPRECOVER}" --dump=tdata in.lz | "${LZIPRECOVER}" -q -Fr --fec-file=- \
	in.lz -o fixed.lz || test_failed $LINENO
cmp "${in_lz}" fixed.lz || test_failed $LINENO
"${LZIPRECOVER}" --remove=tdata in.lz || test_failed $LINENO
cmp "${in_lz}" in.lz || test_failed $LINENO
rm -f in.lz fixed.lz || framework_failure

for i in "${bad1_lz}" "${bad2_lz}" "${bad3_lz}" "${bad4_lz}" "${bad5_lz}" \
         "${bad6_lz}" "${bad7_lz}" "${bad8_lz}" "${bad9_lz}" ; do
  "${LZIPRECOVER}" -q -Fr --fec-file=fecfile.fec "$i" -o fixed.lz ||
    test_failed $LINENO "$i"
  cmp "${in_lz}" fixed.lz || test_failed $LINENO "$i"
  rm -f fixed.lz || framework_failure
done
"${LZIPRECOVER}" -Fc "${in_lz}" -o fec/ || test_failed $LINENO
cmp fec/test.txt.lz.fec fecfile.fec || test_failed $LINENO
"${LZIPRECOVER}" -Ft "${in_lz}" --fec-file=fec/ || test_failed $LINENO
rm -rf fec || framework_failure
mkdir a
mkdir a/bfec
mkdir a/b-fec
mkdir a/b.fec
mkdir a/b_fec
cp fox6.lz "${in_lz}" a || framework_failure
cp "${fox_lz}" a/bfec || framework_failure
cp "${fox_lz}" a/b-fec || framework_failure
cp "${fox_lz}" a/b.fec || framework_failure
cp "${fox_lz}" a/b_fec || framework_failure
"${LZIPRECOVER}" -r -Fc a/ -o fec/ || test_failed $LINENO
[ -e fec/fox6.lz.fec ] || test_failed $LINENO
[ -e fec/bfec/fox.lz.fec ] || test_failed $LINENO
[ ! -e fec/b-fec ] || test_failed $LINENO
[ ! -e fec/b.fec ] || test_failed $LINENO
[ ! -e fec/b_fec ] || test_failed $LINENO
cmp fec/test.txt.lz.fec fecfile.fec || test_failed $LINENO
"${LZIPRECOVER}" -r -Fc a -o fec/ || test_failed $LINENO
[ -e fec/a/fox6.lz.fec ] || test_failed $LINENO
[ -e fec/a/bfec/fox.lz.fec ] || test_failed $LINENO
[ ! -e fec/a/b-fec ] || test_failed $LINENO
[ ! -e fec/a/b.fec ] || test_failed $LINENO
[ ! -e fec/a/b_fec ] || test_failed $LINENO
cmp fec/a/test.txt.lz.fec fecfile.fec || test_failed $LINENO
rm -rf a fec fecfile.fec || framework_failure

printf "\ntesting --merge..."

rm -f out.lz || framework_failure
"${LZIPRECOVER}" -m -o out.lz fox6.lz "${f6b1_lz}" || test_failed $LINENO
[ ! -e out.lz ] || test_failed $LINENO
"${LZIPRECOVER}" -m -o out.lz "${f6b1_lz}" fox6.lz || test_failed $LINENO
[ ! -e out.lz ] || test_failed $LINENO
"${LZIPRECOVER}" -m -o out.lz "${bad1_lz}" "${bad2_lz}" "${bad1_lz}" -q
[ $? = 2 ] || test_failed $LINENO
[ ! -e out.lz ] || test_failed $LINENO
"${LZIPRECOVER}" -m -o out.lz "${bad1_lz}" "${bad2_lz}" "${bad2_lz}" -q
[ $? = 2 ] || test_failed $LINENO
[ ! -e out.lz ] || test_failed $LINENO
cp "${bad2_lz}" bad2.lz || framework_failure
"${LZIPRECOVER}" -m -o out.lz "${bad1_lz}" "${bad2_lz}" bad2.lz -q
[ $? = 2 ] || test_failed $LINENO
[ ! -e out.lz ] || test_failed $LINENO
rm -f bad2.lz || framework_failure
"${LZIPRECOVER}" -m -o out.lz "${f6b1_lz}" "${f6b5_lz}" -q
[ $? = 2 ] || test_failed $LINENO
[ ! -e out.lz ] || test_failed $LINENO
"${LZIPRECOVER}" -m -o out.lz "${f6b3_lz}" "${f6b5_lz}" -q
[ $? = 2 ] || test_failed $LINENO
[ ! -e out.lz ] || test_failed $LINENO
"${LZIPRECOVER}" -m -o out.lz "${bad3_lz}" "${bad4_lz}" -q
[ $? = 2 ] || test_failed $LINENO
[ ! -e out.lz ] || test_failed $LINENO

"${LZIPRECOVER}" -mf -o out.lz "${f6b1_lz}" "${f6b4_lz}" || test_failed $LINENO
cmp fox6.lz out.lz || test_failed $LINENO
"${LZIPRECOVER}" -mf -o out.lz "${f6b4_lz}" "${f6b1_lz}" || test_failed $LINENO
cmp fox6.lz out.lz || test_failed $LINENO
"${LZIPRECOVER}" -m -o a/b/c/out.lz "${f6b1_lz}" "${f6b4_lz}" ||
	test_failed $LINENO
cmp fox6.lz a/b/c/out.lz || test_failed $LINENO
rm -rf a || framework_failure

for i in "${f6b1_lz}" "${f6b3_lz}" "${f6b4_lz}" "${f6b5_lz}" "${f6b6_lz}" ; do
	"${LZIPRECOVER}" -mf -o out.lz "${f6b2_lz}" "$i" ||
		test_failed $LINENO "$i"
	cmp fox6.lz out.lz || test_failed $LINENO "$i"
	"${LZIPRECOVER}" -mf -o out.lz "$i" "${f6b2_lz}" ||
		test_failed $LINENO "$i"
	cmp fox6.lz out.lz || test_failed $LINENO "$i"
done

for i in "${f6b3_lz}" "${f6b4_lz}" "${f6b5_lz}" "${f6b6_lz}" ; do
	"${LZIPRECOVER}" -mf -o out.lz "${f6b1_lz}" "${f6b2_lz}" "$i" ||
		test_failed $LINENO "$i"
	cmp fox6.lz out.lz || test_failed $LINENO "$i"
	"${LZIPRECOVER}" -mf -o out.lz "${f6b1_lz}" "$i" "${f6b2_lz}" ||
		test_failed $LINENO "$i"
	cmp fox6.lz out.lz || test_failed $LINENO "$i"
	"${LZIPRECOVER}" -mf -o out.lz "${f6b2_lz}" "${f6b1_lz}" "$i" ||
		test_failed $LINENO "$i"
	cmp fox6.lz out.lz || test_failed $LINENO "$i"
	"${LZIPRECOVER}" -mf -o out.lz "${f6b2_lz}" "$i" "${f6b1_lz}" ||
		test_failed $LINENO "$i"
	cmp fox6.lz out.lz || test_failed $LINENO "$i"
	"${LZIPRECOVER}" -mf -o out.lz "$i" "${f6b1_lz}" "${f6b2_lz}" ||
		test_failed $LINENO "$i"
	cmp fox6.lz out.lz || test_failed $LINENO "$i"
	"${LZIPRECOVER}" -mf -o out.lz "$i" "${f6b2_lz}" "${f6b1_lz}" ||
		test_failed $LINENO "$i"
	cmp fox6.lz out.lz || test_failed $LINENO "$i"
done

"${LZIPRECOVER}" -mf -o out.lz "${f6b3_lz}" "${f6b4_lz}" "${f6b5_lz}" ||
	test_failed $LINENO
cmp fox6.lz out.lz || test_failed $LINENO
"${LZIPRECOVER}" -mf -o out.lz "${f6b1_lz}" "${f6b3_lz}" "${f6b4_lz}" \
	"${f6b5_lz}" || test_failed $LINENO
cmp fox6.lz out.lz || test_failed $LINENO
"${LZIPRECOVER}" -mf -o out.lz "${f6b2_lz}" "${f6b3_lz}" "${f6b4_lz}" \
	"${f6b5_lz}" || test_failed $LINENO
cmp fox6.lz out.lz || test_failed $LINENO
"${LZIPRECOVER}" -mf -o out.lz "${f6b1_lz}" "${f6b2_lz}" "${f6b3_lz}" \
	"${f6b4_lz}" "${f6b5_lz}" || test_failed $LINENO
cmp fox6.lz out.lz || test_failed $LINENO

"${LZIPRECOVER}" -mf -o out.lz "${bad1_lz}" "${bad2_lz}" || test_failed $LINENO
cmp "${in_lz}" out.lz || test_failed $LINENO
"${LZIPRECOVER}" -mf -o out.lz "${bad2_lz}" "${bad1_lz}" || test_failed $LINENO
cmp "${in_lz}" out.lz || test_failed $LINENO

cat "${in_lz}" "${in_lz}" "${in_lz}" "${in_lz}" > in4.lz || framework_failure
cat "${bad1_lz}" "${in_lz}" "${bad1_lz}" "${bad1_lz}" > bad11.lz || framework_failure
cat "${bad1_lz}" "${in_lz}" "${bad2_lz}" "${in_lz}" > bad12.lz || framework_failure
cat "${bad2_lz}" "${in_lz}" "${bad2_lz}" "${bad2_lz}" > bad22.lz || framework_failure
"${LZIPRECOVER}" -mf -o out4.lz bad11.lz bad12.lz bad22.lz || test_failed $LINENO
cmp in4.lz out4.lz || test_failed $LINENO
"${LZIPRECOVER}" -mf -o out4.lz bad11.lz bad22.lz bad12.lz || test_failed $LINENO
cmp in4.lz out4.lz || test_failed $LINENO
"${LZIPRECOVER}" -mf -o out4.lz bad12.lz bad11.lz bad22.lz || test_failed $LINENO
cmp in4.lz out4.lz || test_failed $LINENO
"${LZIPRECOVER}" -mf -o out4.lz bad12.lz bad22.lz bad11.lz || test_failed $LINENO
cmp in4.lz out4.lz || test_failed $LINENO
"${LZIPRECOVER}" -mf -o out4.lz bad22.lz bad11.lz bad12.lz || test_failed $LINENO
cmp in4.lz out4.lz || test_failed $LINENO
"${LZIPRECOVER}" -mf -o out4.lz bad22.lz bad12.lz bad11.lz || test_failed $LINENO
cmp in4.lz out4.lz || test_failed $LINENO
rm -f bad11.lz bad12.lz bad22.lz || framework_failure

for i in "${bad1_lz}" "${bad2_lz}" ; do
	for j in "${bad3_lz}" "${bad4_lz}" "${bad5_lz}" ; do
		"${LZIPRECOVER}" -mf -o out.lz "$i" "$j" ||
			test_failed $LINENO "$i $j"
		cmp "${in_lz}" out.lz || test_failed $LINENO "$i $j"
		"${LZIPRECOVER}" -mf -o out.lz "$j" "$i" ||
			test_failed $LINENO "$i $j"
		cmp "${in_lz}" out.lz || test_failed $LINENO "$i $j"
	done
done

"${LZIPRECOVER}" -mf -o out.lz "${bad3_lz}" "${bad4_lz}" "${bad5_lz}" ||
	test_failed $LINENO
cmp "${in_lz}" out.lz || test_failed $LINENO
"${LZIPRECOVER}" -mf -o out.lz "${bad3_lz}" "${bad5_lz}" "${bad4_lz}" ||
	test_failed $LINENO
cmp "${in_lz}" out.lz || test_failed $LINENO
"${LZIPRECOVER}" -mf -o out.lz "${bad4_lz}" "${bad3_lz}" "${bad5_lz}" ||
	test_failed $LINENO
cmp "${in_lz}" out.lz || test_failed $LINENO
"${LZIPRECOVER}" -mf -o out.lz "${bad4_lz}" "${bad5_lz}" "${bad3_lz}" ||
	test_failed $LINENO
cmp "${in_lz}" out.lz || test_failed $LINENO
"${LZIPRECOVER}" -mf -o out.lz "${bad5_lz}" "${bad3_lz}" "${bad4_lz}" ||
	test_failed $LINENO
cmp "${in_lz}" out.lz || test_failed $LINENO
"${LZIPRECOVER}" -mf -o out.lz "${bad5_lz}" "${bad4_lz}" "${bad3_lz}" ||
	test_failed $LINENO
cmp "${in_lz}" out.lz || test_failed $LINENO
rm -f out.lz || framework_failure

cat "${bad3_lz}" "${bad4_lz}" "${bad5_lz}" "${in_lz}" > bad345.lz || framework_failure
cat "${bad4_lz}" "${bad5_lz}" "${bad3_lz}" "${in_lz}" > bad453.lz || framework_failure
cat "${bad5_lz}" "${bad3_lz}" "${bad4_lz}" "${in_lz}" > bad534.lz || framework_failure
"${LZIPRECOVER}" -mf -o out4.lz bad345.lz bad453.lz bad534.lz ||
	test_failed $LINENO
cmp in4.lz out4.lz || test_failed $LINENO
"${LZIPRECOVER}" -mf -o out4.lz bad345.lz bad534.lz bad453.lz ||
	test_failed $LINENO
cmp in4.lz out4.lz || test_failed $LINENO
"${LZIPRECOVER}" -mf -o out4.lz bad453.lz bad345.lz bad534.lz ||
	test_failed $LINENO
cmp in4.lz out4.lz || test_failed $LINENO
"${LZIPRECOVER}" -mf -o out4.lz bad453.lz bad534.lz bad345.lz ||
	test_failed $LINENO
cmp in4.lz out4.lz || test_failed $LINENO
"${LZIPRECOVER}" -mf -o out4.lz bad534.lz bad345.lz bad453.lz ||
	test_failed $LINENO
cmp in4.lz out4.lz || test_failed $LINENO
"${LZIPRECOVER}" -mf -o out4.lz bad534.lz bad453.lz bad345.lz ||
	test_failed $LINENO
cmp in4.lz out4.lz || test_failed $LINENO
rm -f bad345.lz bad453.lz bad534.lz out4.lz || framework_failure

printf "\ntesting --reproduce..."

if ${LZIP_NAME} -qs18KiB < in > out && cmp "${in_lz}" out ; then
  rm -f out || framework_failure
  "${LZIPRECOVER}" --reproduce --lzip-name="${LZIP_NAME}" -o out \
    --reference-file=foo "${in_lz}" || test_failed $LINENO "${LZIP_NAME}"
  [ ! -e out ] || test_failed $LINENO
  "${LZIPRECOVER}" --reproduce --lzip-name="${LZIP_NAME}" -o a/b/c/out \
    --reference-file=in "${bad6_lz}" > /dev/null ||
    test_failed $LINENO "${LZIP_NAME}"
  cmp "${in_lz}" a/b/c/out || test_failed $LINENO "${LZIP_NAME}"
  rm -rf a || framework_failure

  for i in 6 7 8 9 ; do
    for f in "${testdir}"/test_bad${i}.txt in ; do
      rm -f out || framework_failure
      "${LZIPRECOVER}" --reproduce --lzip-name="${LZIP_NAME}" -o out \
        --reference-file="$f" "${testdir}"/test_bad${i}.lz > /dev/null ||
        test_failed $LINENO "${LZIP_NAME} $i $f"
      cmp "${in_lz}" out || test_failed $LINENO "${LZIP_NAME} $i $f"
      rm -f out || framework_failure
      "${LZIPRECOVER}" --reproduce --lzip-name="${LZIP_NAME}" -o out \
        --lzip-level=6 --reference-file="$f" "${testdir}"/test_bad${i}.lz \
        > /dev/null || test_failed $LINENO "${LZIP_NAME} $i $f level=6"
      cmp "${in_lz}" out || test_failed $LINENO "${LZIP_NAME} $i $f level=6"
      rm -f out || framework_failure
      "${LZIPRECOVER}" --reproduce --lzip-name="${LZIP_NAME}" -o out \
        --lzip-level=m36 --reference-file="$f" "${testdir}"/test_bad${i}.lz \
        > /dev/null || test_failed $LINENO "${LZIP_NAME} $i $f level=m36"
      cmp "${in_lz}" out || test_failed $LINENO "${LZIP_NAME} $i $f level=m36"
    done
  done

  # multimember reproduction using test_bad[6789].txt as reference
  cat "${bad6_lz}" "${bad7_lz}" "${bad8_lz}" "${bad9_lz}" > mm_bad.lz ||
    framework_failure
  rm -f out || framework_failure
  for i in 6 7 8 9 ; do			# reproduce one member each time
    "${LZIPRECOVER}" --reproduce --lzip-name="${LZIP_NAME}" mm_bad.lz \
      --reference-file="${testdir}"/test_bad${i}.txt -o out > /dev/null ||
      test_failed $LINENO "${LZIP_NAME} $i"
    mv out mm_bad.lz || framework_failure
  done
  cmp in4.lz mm_bad.lz || test_failed $LINENO "${LZIP_NAME}"

  # multimember reproduction using test.txt as reference
  cat "${bad6_lz}" "${bad7_lz}" "${bad8_lz}" "${bad9_lz}" > mm_bad.lz ||
    framework_failure
  rm -f out || framework_failure
  for i in 6 7 8 9 ; do			# reproduce one member each time
    "${LZIPRECOVER}" --reproduce --lzip-name="${LZIP_NAME}" mm_bad.lz -o out \
      --reference-file=in > /dev/null || test_failed $LINENO "${LZIP_NAME} $i"
    mv out mm_bad.lz || framework_failure
  done
  cmp in4.lz mm_bad.lz || test_failed $LINENO "${LZIP_NAME}"
  rm -f mm_bad.lz || framework_failure

  "${LZIPRECOVER}" --reference-file=in "${in_lz}" --lzip-name="${LZIP_NAME}" \
    --debug-reproduce=13-7356 > /dev/null || test_failed $LINENO "${LZIP_NAME}"

  "${LZIPRECOVER}" --debug-reproduce=512,5120,512 --lzip-name="${LZIP_NAME}" \
    -q --reference-file=in "${in_lz}" || test_failed $LINENO "${LZIP_NAME}"
else
  printf "warning: skipping --reproduce test: "
  printf "${LZIP_NAME} not the right compressor, not the right version, or this is not a POSIX system.\n"
  ${LZIP_NAME} -V | sed -e 1q
  printf "Try 'make LZIP_NAME=<name_of_lzip_executable> check'.\n"
fi
rm -f in4.lz || framework_failure

printf "\ntesting --split..."

cat "${in_lz}" "${in_lz}" "${in_lz}" "${in_lz}" "${in_lz}" "${in_lz}" \
    "${in_lz}" "${in_lz}" "${in_lz}" > in9.lz || framework_failure
"${LZIPRECOVER}" -s -o a/b/c/in9.lz in9.lz || test_failed $LINENO
for i in 1 2 3 4 5 6 7 8 9 ; do
	cmp "${in_lz}" a/b/c/rec${i}in9.lz || test_failed $LINENO $i
	"${LZIP}" -cd a/b/c/rec${i}in9.lz > out || test_failed $LINENO $i
	cmp in out || test_failed $LINENO $i
done
cat a/b/c/rec*in9.lz | cmp in9.lz - || test_failed $LINENO
rm -rf a || framework_failure

cp in9.lz in9t.lz || framework_failure
printf "garbage" >> in9t.lz || framework_failure
"${LZIPRECOVER}" -s in9t.lz || test_failed $LINENO
for i in 01 02 03 04 05 06 07 08 09 ; do
	cmp "${in_lz}" rec${i}in9t.lz || test_failed $LINENO $i
	"${LZIP}" -cd rec${i}in9t.lz > out || test_failed $LINENO $i
	cmp in out || test_failed $LINENO $i
done
[ -e rec10in9t.lz ] || test_failed $LINENO
[ ! -e rec11in9t.lz ] || test_failed $LINENO
cat rec*in9t.lz | cmp in9t.lz - || test_failed $LINENO
rm -f rec*in9t.lz in9t.lz || framework_failure

printf "LZIP\001+" > in9t.lz || framework_failure	# gap size < 36 bytes
cat "${in_lz}" "${in_lz}" "${in_lz}" in "${in_lz}" "${in_lz}" "${in_lz}" \
    "${in_lz}" "${in_lz}" "${in_lz}" in >> in9t.lz || framework_failure
"${LZIPRECOVER}" -s in9t.lz || test_failed $LINENO
for i in 02 03 04 06 07 08 09 10 11 ; do
	cmp "${in_lz}" rec${i}in9t.lz || test_failed $LINENO $i
	"${LZIP}" -cd rec${i}in9t.lz > out || test_failed $LINENO $i
	cmp in out || test_failed $LINENO $i
done
cmp in rec05in9t.lz || test_failed $LINENO
cmp in rec12in9t.lz || test_failed $LINENO
[ -e rec01in9t.lz ] || test_failed $LINENO
[ ! -e rec13in9t.lz ] || test_failed $LINENO
cat rec*in9t.lz | cmp in9t.lz - || test_failed $LINENO
rm -f rec*in9t.lz in9t.lz || framework_failure

cat "${in_lz}" "${in_lz}" "${in_lz}" "${in_lz}" "${in_lz}" "${in_lz}" \
    "${in_lz}" "${in_lz}" in "${in_lz}" > in9t.lz || framework_failure
printf "LZIP\001-" >> in9t.lz || framework_failure	# truncated member
"${LZIPRECOVER}" -s in9t.lz || test_failed $LINENO
for i in 01 02 03 04 05 06 07 08 10 ; do
	cmp "${in_lz}" rec${i}in9t.lz || test_failed $LINENO $i
	"${LZIP}" -cd rec${i}in9t.lz > out || test_failed $LINENO $i
	cmp in out || test_failed $LINENO $i
done
cmp in rec09in9t.lz || test_failed $LINENO
[ -e rec11in9t.lz ] || test_failed $LINENO
[ ! -e rec12in9t.lz ] || test_failed $LINENO
cat rec*in9t.lz | cmp in9t.lz - || test_failed $LINENO
rm -f rec*in9t.lz in9t.lz || framework_failure

cat "${in_lz}" "${in_lz}" "${in_lz}" in "${in_lz}" > in9t.lz || framework_failure
printf "LZIP\001-" >> in9t.lz || framework_failure	# truncated member
cat "${in_lz}" "${in_lz}" "${in_lz}" "${in_lz}" "${in_lz}" >> in9t.lz ||
	framework_failure
"${LZIPRECOVER}" -s in9t.lz || test_failed $LINENO
for i in 01 02 03 05 07 08 09 10 11 ; do
	cmp "${in_lz}" rec${i}in9t.lz || test_failed $LINENO $i
	"${LZIP}" -cd rec${i}in9t.lz > out || test_failed $LINENO $i
	cmp in out || test_failed $LINENO $i
done
cmp in rec04in9t.lz || test_failed $LINENO
[ -e rec06in9t.lz ] || test_failed $LINENO
[ ! -e rec12in9t.lz ] || test_failed $LINENO
cat rec*in9t.lz | cmp in9t.lz - || test_failed $LINENO
rm -f rec*in9t.lz in9t.lz || framework_failure

"${LZIPRECOVER}" -s "${f6b1_lz}" -o f6.lz || test_failed $LINENO
for i in 1 2 3 4 5 6 ; do
	[ -e rec${i}f6.lz ] || test_failed $LINENO
done
[ ! -e rec7f6.lz ] || test_failed $LINENO
cat rec*f6.lz | cmp "${f6b1_lz}" - || test_failed $LINENO
rm -f rec*f6.lz || framework_failure

"${LZIPRECOVER}" -s "${f6b2_lz}" -o f6.lz || test_failed $LINENO
for i in 1 3 4 5 6 ; do
	cmp "${fox_lz}" rec${i}f6.lz || test_failed $LINENO
done
[ -e rec2f6.lz ] || test_failed $LINENO
[ ! -e rec7f6.lz ] || test_failed $LINENO
cat rec*f6.lz | cmp "${f6b2_lz}" - || test_failed $LINENO
rm -f rec*f6.lz || framework_failure

"${LZIPRECOVER}" -s "${f6b3_lz}" -o f6.lz || test_failed $LINENO
for i in 1 2 4 ; do
	cmp "${fox_lz}" rec${i}f6.lz || test_failed $LINENO
done
[ -e rec3f6.lz ] || test_failed $LINENO
[ ! -e rec5f6.lz ] || test_failed $LINENO
cat rec*f6.lz | cmp "${f6b3_lz}" - || test_failed $LINENO
rm -f rec*f6.lz || framework_failure

for i in "${f6b4_lz}" "${f6b5_lz}" ; do
	"${LZIPRECOVER}" -s "$i" -o f6.lz || test_failed $LINENO
	for j in 1 2 3 4 ; do
		cmp "${fox_lz}" rec${j}f6.lz || test_failed $LINENO
	done
	[ -e rec5f6.lz ] || test_failed $LINENO
	[ ! -e rec6f6.lz ] || test_failed $LINENO
	cat rec*f6.lz | cmp "$i" - || test_failed $LINENO
	rm -f rec*f6.lz || framework_failure
done

"${LZIPRECOVER}" -s "${f6b6_lz}" -o f6.lz || test_failed $LINENO
for i in 1 2 3 4 5 ; do
	cmp "${fox_lz}" rec${i}f6.lz || test_failed $LINENO
done
[ -e rec6f6.lz ] || test_failed $LINENO
[ ! -e rec7f6.lz ] || test_failed $LINENO
cat rec*f6.lz | cmp "${f6b6_lz}" - || test_failed $LINENO
rm -f rec*f6.lz || framework_failure

"${LZIPRECOVER}" -s "${f6s1_lz}" -o f6.lz || test_failed $LINENO
for i in 1 2 3 4 5 ; do
	cmp "${fox_lz}" rec${i}f6.lz || test_failed $LINENO
done
[ -e rec6f6.lz ] || test_failed $LINENO
[ ! -e rec7f6.lz ] || test_failed $LINENO
cat rec*f6.lz | cmp "${f6s1_lz}" - || test_failed $LINENO
rm -f rec*f6.lz || framework_failure
for i in "${f6s2_lz}" "${f6s3_lz}" "${f6s4_lz}" "${f6s5_lz}" "${f6s6_lz}" ; do
	"${LZIPRECOVER}" -s "$i" -o f6.lz || test_failed $LINENO "$i"
	for j in 1 2 3 4 5 6 ; do
		cmp "${fox_lz}" rec${j}f6.lz || test_failed $LINENO "$i $j"
	done
	[ -e rec7f6.lz ] || test_failed $LINENO "$i"
	[ ! -e rec8f6.lz ] || test_failed $LINENO "$i"
	cat rec*f6.lz | cmp "$i" - || test_failed $LINENO "$i"
	rm -f rec*f6.lz || framework_failure
done

"${LZIPRECOVER}" -s ingin.lz || test_failed $LINENO
cmp "${in_lz}" rec1ingin.lz || test_failed $LINENO
cmp "${in_lz}" rec3ingin.lz || test_failed $LINENO
printf "g" | cmp rec2ingin.lz - || test_failed $LINENO
[ ! -e rec4ingin.lz ] || test_failed $LINENO
cat rec*ingin.lz | cmp ingin.lz - || test_failed $LINENO
rm -f rec*ingin.lz || framework_failure

printf "\ntesting --dump/remove/strip..."

"${LZIPRECOVER}" --dump=1 "${in_lz}" -o a/b/c/out.lz || test_failed $LINENO
cmp "${in_lz}" a/b/c/out.lz || test_failed $LINENO
rm -rf a || framework_failure

"${LZIPRECOVER}" -s "${num_lz}" -o num.lz || test_failed $LINENO
[ -e rec9num.lz ] || test_failed $LINENO
[ ! -e rec10num.lz ] || test_failed $LINENO
cat rec*num.lz | cmp "${num_lz}" - || test_failed $LINENO
for i in 1 2 3 4 5 6 7 8 9 ; do
	"${LZIPRECOVER}" --dump=$i "${num_lz}" | cmp rec${i}num.lz - ||
		test_failed $LINENO $i
	"${LZIPRECOVER}" --strip=^$i "${num_lz}" | cmp rec${i}num.lz - ||
		test_failed $LINENO $i
	cp "${num_lz}" num.lz || framework_failure
	"${LZIPRECOVER}" --remove=^$i num.lz || test_failed $LINENO $i
	cmp rec${i}num.lz num.lz || test_failed $LINENO $i
done
"${LZIPRECOVER}" -q --dump=1 in "${num_lz}" > out
[ $? = 2 ] || test_failed $LINENO
cmp rec1num.lz out || test_failed $LINENO
"${LZIPRECOVER}" -q --strip=^1 in "${num_lz}" > out
[ $? = 2 ] || test_failed $LINENO
cmp rec1num.lz out || test_failed $LINENO

"${LZIPRECOVER}" --dump=r1 "${num_lz}" | cmp rec9num.lz - ||
	test_failed $LINENO
"${LZIPRECOVER}" --dump=d:r3 "${num_lz}" | cmp rec7num.lz - ||
	test_failed $LINENO
"${LZIPRECOVER}" --dump=r5:d "${num_lz}" | cmp rec5num.lz - ||
	test_failed $LINENO
"${LZIPRECOVER}" --dump=t:r9 "${num_lz}" | cmp rec1num.lz - ||
	test_failed $LINENO
"${LZIPRECOVER}" --strip=r^1:t "${num_lz}" | cmp rec9num.lz - ||
	test_failed $LINENO
"${LZIPRECOVER}" --strip=d:r^3:t "${num_lz}" | cmp rec7num.lz - ||
	test_failed $LINENO
"${LZIPRECOVER}" --strip=r^5:d:t "${num_lz}" | cmp rec5num.lz - ||
	test_failed $LINENO
"${LZIPRECOVER}" --strip=d:t:r^9 "${num_lz}" | cmp rec1num.lz - ||
	test_failed $LINENO

"${LZIPRECOVER}" --dump=1,5 "${num_lz}" > out || test_failed $LINENO
cat rec1num.lz rec5num.lz | cmp out - || test_failed $LINENO
"${LZIPRECOVER}" --dump=3,6 "${num_lz}" > out || test_failed $LINENO
cat rec3num.lz rec6num.lz | cmp out - || test_failed $LINENO
"${LZIPRECOVER}" --dump=2-4 "${num_lz}" > out || test_failed $LINENO
cat rec2num.lz rec3num.lz rec4num.lz | cmp out - || test_failed $LINENO
"${LZIPRECOVER}" --dump=4,6,8 "${num_lz}" > out || test_failed $LINENO
cat rec4num.lz rec6num.lz rec8num.lz | cmp out - || test_failed $LINENO
"${LZIPRECOVER}" --strip=^1,5 "${num_lz}" > out || test_failed $LINENO
cat rec1num.lz rec5num.lz | cmp out - || test_failed $LINENO
"${LZIPRECOVER}" --strip=^3,6 "${num_lz}" > out || test_failed $LINENO
cat rec3num.lz rec6num.lz | cmp out - || test_failed $LINENO
"${LZIPRECOVER}" --strip=^2-4 "${num_lz}" > out || test_failed $LINENO
cat rec2num.lz rec3num.lz rec4num.lz | cmp out - || test_failed $LINENO
"${LZIPRECOVER}" --strip=^4,6,8 "${num_lz}" > out || test_failed $LINENO
cat rec4num.lz rec6num.lz rec8num.lz | cmp out - || test_failed $LINENO

# create a subset tarlz archive
"${LZIPRECOVER}" --dump=1-2:r1:t "${num_lz}" > out || test_failed $LINENO
cat rec1num.lz rec2num.lz rec9num.lz | cmp out - || test_failed $LINENO
"${LZIPRECOVER}" --dump=4-5:r1:t "${num_lz}" > out || test_failed $LINENO
cat rec4num.lz rec5num.lz rec9num.lz | cmp out - || test_failed $LINENO
"${LZIPRECOVER}" --dump=7-8:r1:t "${num_lz}" > out || test_failed $LINENO
cat rec7num.lz rec8num.lz rec9num.lz | cmp out - || test_failed $LINENO

"${LZIPRECOVER}" --dump=1-9 "${num_lz}" | cmp "${num_lz}" - ||
	test_failed $LINENO
"${LZIPRECOVER}" --dump=r1-9 "${num_lz}" | cmp "${num_lz}" - ||
	test_failed $LINENO
"${LZIPRECOVER}" --dump=1-1000 "${num_lz}" | cmp "${num_lz}" - ||
	test_failed $LINENO
"${LZIPRECOVER}" --dump=r1-1000 "${num_lz}" | cmp "${num_lz}" - ||
	test_failed $LINENO
"${LZIPRECOVER}" --dump=1-4:r1-4:5 "${num_lz}" | cmp "${num_lz}" - ||
	test_failed $LINENO
"${LZIPRECOVER}" --dump=^10 "${num_lz}" | cmp "${num_lz}" - ||
	test_failed $LINENO
"${LZIPRECOVER}" --strip=^1-9 "${num_lz}" | cmp "${num_lz}" - ||
	test_failed $LINENO
"${LZIPRECOVER}" --strip=r^1-9 "${num_lz}" | cmp "${num_lz}" - ||
	test_failed $LINENO
"${LZIPRECOVER}" --strip=^1-1000 "${num_lz}" | cmp "${num_lz}" - ||
	test_failed $LINENO
"${LZIPRECOVER}" --strip=r^1-1000 "${num_lz}" | cmp "${num_lz}" - ||
	test_failed $LINENO
"${LZIPRECOVER}" --strip=^1-4:r^1-4:^5 "${num_lz}" | cmp "${num_lz}" - ||
	test_failed $LINENO
"${LZIPRECOVER}" --strip=10 "${num_lz}" | cmp "${num_lz}" - ||
	test_failed $LINENO

"${LZIPRECOVER}" -i --dump=r1 "${nbt_lz}" | cmp rec9num.lz - ||
	test_failed $LINENO
"${LZIPRECOVER}" -i --dump=r3 "${nbt_lz}" | cmp rec7num.lz - ||
	test_failed $LINENO
"${LZIPRECOVER}" -i --dump=r7 "${nbt_lz}" | cmp rec4num.lz - ||
	test_failed $LINENO
"${LZIPRECOVER}" -i --strip=r^1:t "${nbt_lz}" | cmp rec9num.lz - ||
	test_failed $LINENO
"${LZIPRECOVER}" -i --strip=r^3:t "${nbt_lz}" | cmp rec7num.lz - ||
	test_failed $LINENO
"${LZIPRECOVER}" -i --strip=r^7:t "${nbt_lz}" | cmp rec4num.lz - ||
	test_failed $LINENO

"${LZIPRECOVER}" -i --dump=4 -f -o out "${nbt_lz}" || test_failed $LINENO
printf "gap" | cmp out - || test_failed $LINENO
"${LZIPRECOVER}" -i --dump=8 "${nbt_lz}" > out || test_failed $LINENO
printf "damaged" | cmp out - || test_failed $LINENO
"${LZIPRECOVER}" -i --dump=tdata "${nbt_lz}" > out || test_failed $LINENO
printf "trailing data" | cmp out - || test_failed $LINENO
"${LZIPRECOVER}" -i --dump=4:t "${nbt_lz}" > out || test_failed $LINENO
printf "gaptrailing data" | cmp out - || test_failed $LINENO
"${LZIPRECOVER}" -i --dump=4,8:t "${nbt_lz}" > out || test_failed $LINENO
printf "gapdamagedtrailing data" | cmp out - || test_failed $LINENO
"${LZIPRECOVER}" -i --dump=4,8 "${nbt_lz}" > out || test_failed $LINENO
printf "gapdamaged" | cmp out - || test_failed $LINENO
"${LZIPRECOVER}" -i --dump=damaged "${nbt_lz}" > out || test_failed $LINENO
printf "gapdamaged" | cmp out - || test_failed $LINENO
"${LZIPRECOVER}" -i --dump=d:t "${nbt_lz}" > out || test_failed $LINENO
printf "gapdamagedtrailing data" | cmp out - || test_failed $LINENO
"${LZIPRECOVER}" -i --strip=^4:t -f -o out "${nbt_lz}" || test_failed $LINENO
printf "gap" | cmp out - || test_failed $LINENO
"${LZIPRECOVER}" -i --strip=^8:t "${nbt_lz}" > out || test_failed $LINENO
printf "damaged" | cmp out - || test_failed $LINENO
"${LZIPRECOVER}" -i --strip=1-11 "${nbt_lz}" > out || test_failed $LINENO
cmp empty out || test_failed $LINENO
"${LZIPRECOVER}" -i --strip=^4 "${nbt_lz}" > out || test_failed $LINENO
printf "gaptrailing data" | cmp out - || test_failed $LINENO
"${LZIPRECOVER}" -i --strip=^4,8 "${nbt_lz}" > out || test_failed $LINENO
printf "gapdamagedtrailing data" | cmp out - || test_failed $LINENO
"${LZIPRECOVER}" -i --strip=^4,8:t "${nbt_lz}" > out || test_failed $LINENO
printf "gapdamaged" | cmp out - || test_failed $LINENO
"${LZIPRECOVER}" -i --strip=r^4,8:t "${nbt_lz}" > out || test_failed $LINENO
printf "gapdamaged" | cmp out - || test_failed $LINENO
"${LZIPRECOVER}" -i --strip=r^4,8 "${nbt_lz}" > out || test_failed $LINENO
printf "gapdamagedtrailing data" | cmp out - || test_failed $LINENO

cp "${num_lz}" num.lz || framework_failure
"${LZIPRECOVER}" --remove=1-3,5,7,9 num.lz || test_failed $LINENO
cat rec4num.lz rec6num.lz rec8num.lz | cmp num.lz - || test_failed $LINENO
cp "${num_lz}" num.lz || framework_failure
"${LZIPRECOVER}" --remove=^4,6,8 num.lz || test_failed $LINENO
cat rec4num.lz rec6num.lz rec8num.lz | cmp num.lz - || test_failed $LINENO
cp "${num_lz}" num.lz || framework_failure
"${LZIPRECOVER}" --remove=r1,3,5,7-9 num.lz || test_failed $LINENO
cat rec4num.lz rec6num.lz rec8num.lz | cmp num.lz - || test_failed $LINENO
cp "${num_lz}" num.lz || framework_failure
"${LZIPRECOVER}" --remove=r^2,4,6 num.lz || test_failed $LINENO
cat rec4num.lz rec6num.lz rec8num.lz | cmp num.lz - || test_failed $LINENO
rm -f num.lz || framework_failure

cp "${nbt_lz}" nbt.lz || framework_failure
"${LZIPRECOVER}" -i --remove=4,8:tdata nbt.lz || test_failed $LINENO
cmp "${num_lz}" nbt.lz || test_failed $LINENO
cp "${nbt_lz}" nbt.lz || framework_failure
"${LZIPRECOVER}" -i --remove=r4,8:tdata nbt.lz || test_failed $LINENO
cmp "${num_lz}" nbt.lz || test_failed $LINENO
cp "${nbt_lz}" nbt.lz || framework_failure
"${LZIPRECOVER}" --remove=damaged:tdata nbt.lz || test_failed $LINENO
cmp "${num_lz}" nbt.lz || test_failed $LINENO
rm -f rec*num.lz nbt.lz || framework_failure

for i in 1 2 3 4 5 6 7 8 9 10 ; do
	"${LZIPRECOVER}" -i --strip=1-$i "${nbt_lz}" > out ||
		test_failed $LINENO $i
	cp "${nbt_lz}" nbt.lz || framework_failure
	"${LZIPRECOVER}" -i --remove=1-$i nbt.lz || test_failed $LINENO $i
	cmp nbt.lz out || test_failed $LINENO $i
done
rm -f nbt.lz || framework_failure

cat "${fox_lz}" "${fox_lz}" "${fox_lz}" > fox3.lz || framework_failure
cp f3_em.lz out.lz || framework_failure
"${LZIPRECOVER}" --remove=empty out.lz || test_failed $LINENO
cmp fox3.lz out.lz || test_failed $LINENO
rm -f out.lz || framework_failure
"${LZIPRECOVER}" --dump=2,4,7 f3_em.lz | cmp fox3.lz - || test_failed $LINENO
"${LZIPRECOVER}" --strip=e f3_em.lz | cmp fox3.lz - || test_failed $LINENO
"${LZIPRECOVER}" --strip=1,3,5-6,8 f3_em.lz | cmp fox3.lz - ||
	test_failed $LINENO
"${LZIPRECOVER}" --dump=empty f3_em.lz | "${LZIP}" -d | cmp empty - ||
	test_failed $LINENO

printf "\ntesting --dump/remove/strip=damaged..."

cp "${in_lz}" in.lz || framework_failure
cat "${in_lz}" in > int.lz || framework_failure
"${LZIPRECOVER}" --dump=damaged in.lz > out || test_failed $LINENO
cmp empty out || test_failed $LINENO
"${LZIPRECOVER}" --dump=damage int.lz > out || test_failed $LINENO
cmp empty out || test_failed $LINENO
"${LZIPRECOVER}" --strip=damag in.lz > out || test_failed $LINENO
cmp in.lz out || test_failed $LINENO
"${LZIPRECOVER}" --strip=dama int.lz > out || test_failed $LINENO
cmp int.lz out || test_failed $LINENO
# strip trailing data from all but the last file
"${LZIPRECOVER}" --strip=dam int.lz int.lz > out || test_failed $LINENO
cat "${in_lz}" "${in_lz}" in | cmp out - || test_failed $LINENO
"${LZIPRECOVER}" --remove=da in.lz || test_failed $LINENO
cmp "${in_lz}" in.lz || test_failed $LINENO
"${LZIPRECOVER}" --remove=d int.lz || test_failed $LINENO
cat "${in_lz}" in | cmp int.lz - || test_failed $LINENO
rm -f in.lz int.lz || framework_failure

cat in9.lz in > in9t.lz || framework_failure
"${LZIPRECOVER}" --dump=damaged in9.lz > out || test_failed $LINENO
cmp empty out || test_failed $LINENO
"${LZIPRECOVER}" --dump=damaged in9t.lz > out || test_failed $LINENO
cmp empty out || test_failed $LINENO
"${LZIPRECOVER}" --strip=damaged in9.lz > out || test_failed $LINENO
cmp in9.lz out || test_failed $LINENO
"${LZIPRECOVER}" --strip=damaged in9t.lz > out || test_failed $LINENO
cmp in9t.lz out || test_failed $LINENO
"${LZIPRECOVER}" --remove=damaged in9t.lz || test_failed $LINENO
cat in9.lz in | cmp in9t.lz - || test_failed $LINENO
cp in9.lz in9t.lz || framework_failure
"${LZIPRECOVER}" --remove=damaged in9t.lz || test_failed $LINENO
cmp in9.lz in9t.lz || test_failed $LINENO
rm -f in9t.lz || framework_failure

printf "LZIP\001+" > in9t.lz || framework_failure	# gap size < 36 bytes
cat "${in_lz}" "${in_lz}" "${in_lz}" in "${in_lz}" "${in_lz}" "${in_lz}" \
    "${in_lz}" "${in_lz}" "${in_lz}" >> in9t.lz || framework_failure
printf "LZIP\001-" >> in9t.lz || framework_failure	# truncated member
printf "LZIP\001+" > gaps || framework_failure
cat in >> gaps || framework_failure
printf "LZIP\001-" >> gaps || framework_failure
"${LZIPRECOVER}" --dump=damaged in9t.lz > out || test_failed $LINENO
cmp gaps out || test_failed $LINENO
"${LZIPRECOVER}" --strip=damaged in9t.lz > out || test_failed $LINENO
cmp in9.lz out || test_failed $LINENO
"${LZIPRECOVER}" --remove=damaged in9t.lz || test_failed $LINENO
cmp in9.lz in9t.lz || test_failed $LINENO
rm -f in9.lz in9t.lz gaps || framework_failure

"${LZIPRECOVER}" --dump=damaged "${f6b1_lz}" > out || test_failed $LINENO
cmp "${f6b1_lz}" out || test_failed $LINENO
cat "${f6b1_lz}" in > f6bt.lz || framework_failure
"${LZIPRECOVER}" --dump=damaged f6bt.lz > out || test_failed $LINENO
cmp "${f6b1_lz}" out || test_failed $LINENO
"${LZIPRECOVER}" --strip=damaged "${f6b1_lz}" > out || test_failed $LINENO
cmp empty out || test_failed $LINENO
"${LZIPRECOVER}" --strip=damaged f6bt.lz > out || test_failed $LINENO
cmp empty out || test_failed $LINENO
cp "${f6b1_lz}" f6b.lz || framework_failure
"${LZIPRECOVER}" -q --remove=damaged f6b.lz
[ $? = 2 ] || test_failed $LINENO
cmp "${f6b1_lz}" f6b.lz || test_failed $LINENO
"${LZIPRECOVER}" -q --remove=damaged f6bt.lz
[ $? = 2 ] || test_failed $LINENO
cat "${f6b1_lz}" in | cmp f6bt.lz - || test_failed $LINENO
rm -f f6b.lz f6bt.lz || framework_failure

"${LZIPRECOVER}" --dump=damaged "${f6b2_lz}" > out || test_failed $LINENO
cat "${fox_lz}" out "${fox_lz}" "${fox_lz}" "${fox_lz}" \
    "${fox_lz}" | cmp "${f6b2_lz}" - || test_failed $LINENO
cat "${f6b2_lz}" in > f6bt.lz || framework_failure
"${LZIPRECOVER}" --dump=damaged f6bt.lz > out || test_failed $LINENO
cat "${fox_lz}" out "${fox_lz}" "${fox_lz}" "${fox_lz}" \
    "${fox_lz}" | cmp "${f6b2_lz}" - || test_failed $LINENO
cat "${fox_lz}" "${fox_lz}" "${fox_lz}" "${fox_lz}" "${fox_lz}" > fox5.lz ||
	framework_failure
"${LZIPRECOVER}" --strip=damaged "${f6b2_lz}" > out || test_failed $LINENO
cmp fox5.lz out || test_failed $LINENO
"${LZIPRECOVER}" --strip=damaged f6bt.lz > out || test_failed $LINENO
cat fox5.lz in | cmp out - || test_failed $LINENO
cp "${f6b2_lz}" f6b.lz || framework_failure
"${LZIPRECOVER}" --remove=damaged f6b.lz || test_failed $LINENO
cmp fox5.lz f6b.lz || test_failed $LINENO
"${LZIPRECOVER}" --remove=damaged f6bt.lz || test_failed $LINENO
cat fox5.lz in | cmp f6bt.lz - || test_failed $LINENO
rm -f f6b.lz f6bt.lz || framework_failure

"${LZIPRECOVER}" --dump=damaged "${f6b3_lz}" > out || test_failed $LINENO
cat "${fox_lz}" "${fox_lz}" out "${fox_lz}" | cmp "${f6b3_lz}" - ||
	test_failed $LINENO
cat "${f6b3_lz}" in > f6bt.lz || framework_failure
"${LZIPRECOVER}" --dump=damaged f6bt.lz > out || test_failed $LINENO
cat "${fox_lz}" "${fox_lz}" out "${fox_lz}" | cmp "${f6b3_lz}" - ||
	test_failed $LINENO
"${LZIPRECOVER}" --strip=damaged "${f6b3_lz}" > out || test_failed $LINENO
cmp fox3.lz out || test_failed $LINENO
"${LZIPRECOVER}" --strip=damaged f6bt.lz > out || test_failed $LINENO
cat fox3.lz in | cmp out - || test_failed $LINENO
cp "${f6b3_lz}" f6b.lz || framework_failure
"${LZIPRECOVER}" --remove=damaged f6b.lz || test_failed $LINENO
cmp fox3.lz f6b.lz || test_failed $LINENO
"${LZIPRECOVER}" --remove=damaged f6bt.lz || test_failed $LINENO
cat fox3.lz in | cmp f6bt.lz - || test_failed $LINENO
rm -f f6b.lz f6bt.lz fox3.lz || framework_failure

cat "${fox_lz}" "${fox_lz}" "${fox_lz}" "${fox_lz}" > fox4.lz ||
	framework_failure
for i in "${f6b4_lz}" "${f6b5_lz}" ; do
	"${LZIPRECOVER}" --dump=damaged "$i" > out || test_failed $LINENO "$i"
	cat fox4.lz out | cmp "$i" - || test_failed $LINENO "$i"
	cat "$i" in > f6bt.lz || framework_failure
	"${LZIPRECOVER}" --dump=damaged f6bt.lz > out ||
		test_failed $LINENO "$i"
	cat fox4.lz out | cmp f6bt.lz - || test_failed $LINENO "$i"
	"${LZIPRECOVER}" --strip=damaged "$i" > out || test_failed $LINENO "$i"
	cmp fox4.lz out || test_failed $LINENO "$i"
	"${LZIPRECOVER}" --strip=damaged f6bt.lz > out ||
		test_failed $LINENO "$i"
	cmp fox4.lz out || test_failed $LINENO "$i"
	cp "$i" f6b.lz || framework_failure
	"${LZIPRECOVER}" --remove=damaged f6b.lz || test_failed $LINENO "$i"
	cmp fox4.lz f6b.lz || test_failed $LINENO "$i"
	"${LZIPRECOVER}" --remove=damaged f6bt.lz || test_failed $LINENO "$i"
	cmp fox4.lz f6bt.lz || test_failed $LINENO "$i"
done
rm -f f6b.lz f6bt.lz fox4.lz || framework_failure

"${LZIPRECOVER}" --dump=damaged "${f6b6_lz}" > out || test_failed $LINENO
cat fox5.lz out | cmp "${f6b6_lz}" - || test_failed $LINENO
cat "${f6b6_lz}" in > f6bt.lz || framework_failure
"${LZIPRECOVER}" --dump=damaged f6bt.lz > out || test_failed $LINENO
cat fox5.lz out | cmp "${f6b6_lz}" - || test_failed $LINENO
"${LZIPRECOVER}" --strip=damaged "${f6b6_lz}" > out || test_failed $LINENO
cmp fox5.lz out || test_failed $LINENO
"${LZIPRECOVER}" --strip=damaged f6bt.lz > out || test_failed $LINENO
cat fox5.lz in | cmp out - || test_failed $LINENO
cp "${f6b6_lz}" f6b.lz || framework_failure
"${LZIPRECOVER}" --remove=damaged f6b.lz || test_failed $LINENO
cmp fox5.lz f6b.lz || test_failed $LINENO
"${LZIPRECOVER}" --remove=damaged f6bt.lz || test_failed $LINENO
cat fox5.lz in | cmp f6bt.lz - || test_failed $LINENO
rm -f f6b.lz f6bt.lz || framework_failure

for i in "${f6s1_lz}" "${f6s2_lz}" ; do
	"${LZIPRECOVER}" --dump=damaged "$i" > out || test_failed $LINENO "$i"
	cmp "$i" out || test_failed $LINENO "$i"
	cat "$i" in > f6bt.lz || framework_failure
	"${LZIPRECOVER}" --dump=damaged f6bt.lz > out ||
		test_failed $LINENO "$i"
	cmp "$i" out || test_failed $LINENO "$i"
	"${LZIPRECOVER}" --strip=damaged "$i" > out || test_failed $LINENO "$i"
	cmp empty out || test_failed $LINENO "$i"
	"${LZIPRECOVER}" --strip=damaged f6bt.lz > out ||
		test_failed $LINENO "$i"
	cmp empty out || test_failed $LINENO "$i"
	cp "$i" f6b.lz || framework_failure
	"${LZIPRECOVER}" -q --remove=damaged f6b.lz
	[ $? = 2 ] || test_failed $LINENO "$i"
	cmp "$i" f6b.lz || test_failed $LINENO "$i"
	"${LZIPRECOVER}" -q --remove=damaged f6bt.lz
	[ $? = 2 ] || test_failed $LINENO "$i"
	cat "$i" in | cmp f6bt.lz - || test_failed $LINENO "$i"
done
rm -f f6b.lz f6bt.lz || framework_failure

for i in "${f6s3_lz}" "${f6s4_lz}" "${f6s5_lz}" "${f6s6_lz}" ; do
	"${LZIPRECOVER}" --dump=damaged "$i" > out || test_failed $LINENO "$i"
	cmp empty out || test_failed $LINENO "$i"
	cat "$i" in > f6bt.lz || framework_failure
	"${LZIPRECOVER}" --dump=damaged f6bt.lz > out ||
		test_failed $LINENO "$i"
	cmp empty out || test_failed $LINENO "$i"
	"${LZIPRECOVER}" --strip=damaged "$i" > out || test_failed $LINENO "$i"
	cmp "$i" out || test_failed $LINENO "$i"
	"${LZIPRECOVER}" --strip=damaged f6bt.lz > out ||
		test_failed $LINENO "$i"
	cat "$i" in | cmp out - || test_failed $LINENO "$i"
	cp "$i" f6b.lz || framework_failure
	"${LZIPRECOVER}" --remove=damaged f6b.lz || test_failed $LINENO "$i"
	cmp "$i" f6b.lz || test_failed $LINENO "$i"
	"${LZIPRECOVER}" --remove=damaged f6bt.lz || test_failed $LINENO "$i"
	cat "$i" in | cmp f6bt.lz - || test_failed $LINENO "$i"
done
rm -f f6b.lz f6bt.lz empty || framework_failure

cat ingin.lz "${inD}" > ingint.lz || framework_failure
"${LZIPRECOVER}" --dump=damaged ingin.lz > out || test_failed $LINENO
printf "g" | cmp out - || test_failed $LINENO
"${LZIPRECOVER}" --dump=damaged ingint.lz > out || test_failed $LINENO
printf "g" | cmp out - || test_failed $LINENO
"${LZIPRECOVER}" --strip=damaged ingin.lz > out || test_failed $LINENO
cmp in2.lz out || test_failed $LINENO
"${LZIPRECOVER}" --strip=damaged ingint.lz > out || test_failed $LINENO
cat "${in_lz}" "${in_lz}" "${inD}" | cmp out - || test_failed $LINENO
cp ingin.lz ingin2.lz || framework_failure
"${LZIPRECOVER}" --remove=damaged ingin2.lz || test_failed $LINENO
cmp in2.lz ingin2.lz || test_failed $LINENO
"${LZIPRECOVER}" --remove=damaged ingint.lz || test_failed $LINENO
cat "${in_lz}" "${in_lz}" "${inD}" | cmp ingint.lz - || test_failed $LINENO
rm -f ingin2.lz ingint.lz || framework_failure

# concatenate output from several files
"${LZIPRECOVER}" --dump=damaged "${f6b2_lz}" > out || test_failed $LINENO
"${LZIPRECOVER}" --dump=damaged "${bad2_lz}" "${f6b2_lz}" > out2 ||
	test_failed $LINENO
cat "${bad2_lz}" out | cmp out2 - || test_failed $LINENO
cat "${bad2_lz}" in > bad2t.lz || framework_failure
cat "${f6b2_lz}" in > f6bt.lz || framework_failure
"${LZIPRECOVER}" --dump=damaged bad2t.lz "${f6b2_lz}" "${bad2_lz}" \
	f6bt.lz > out4 || test_failed $LINENO
cat "${bad2_lz}" out "${bad2_lz}" out | cmp out4 - || test_failed $LINENO
"${LZIPRECOVER}" --dump=damaged "${f6b2_lz}" bad2t.lz f6bt.lz \
	"${bad2_lz}" > out4 || test_failed $LINENO
cat out "${bad2_lz}" out "${bad2_lz}" | cmp out4 - || test_failed $LINENO
#
"${LZIPRECOVER}" --strip=damaged "${bad2_lz}" "${f6b2_lz}" > out ||
	test_failed $LINENO
cmp fox5.lz out || test_failed $LINENO
"${LZIPRECOVER}" --strip=damaged bad2t.lz "${f6b2_lz}" > out ||
	test_failed $LINENO
cmp fox5.lz out || test_failed $LINENO
"${LZIPRECOVER}" --strip=damaged "${f6b2_lz}" bad2t.lz f6bt.lz > out ||
	test_failed $LINENO
cat fox5.lz fox5.lz in | cmp out - || test_failed $LINENO
"${LZIPRECOVER}" --strip=damaged "${f6b2_lz}" f6bt.lz bad2t.lz > out ||
	test_failed $LINENO
cat fox5.lz fox5.lz | cmp out - || test_failed $LINENO
"${LZIPRECOVER}" --strip=damaged f6bt.lz bad2t.lz > out ||
	test_failed $LINENO
cmp fox5.lz out || test_failed $LINENO
"${LZIPRECOVER}" --strip=damaged f6bt.lz "${in_lz}" > out ||
	test_failed $LINENO
cat fox5.lz "${in_lz}" | cmp out - || test_failed $LINENO
"${LZIPRECOVER}" --strip=damaged --strip=tdata f6bt.lz "${in_lz}" > out ||
	test_failed $LINENO
cat fox5.lz "${in_lz}" | cmp out - || test_failed $LINENO
#
cp "${f6b2_lz}" f6b.lz || framework_failure
"${LZIPRECOVER}" -q --remove=damaged f6b.lz bad2t.lz f6bt.lz
[ $? = 2 ] || test_failed $LINENO
cat "${bad2_lz}" in | cmp bad2t.lz - || test_failed $LINENO
cmp fox5.lz f6b.lz || test_failed $LINENO
cat fox5.lz in | cmp f6bt.lz - || test_failed $LINENO
cat "${bad2_lz}" in > bad2t.lz || framework_failure
cat fox6.lz "${inD}" > fox6t.lz || framework_failure
cat "${f6b1_lz}" in > f6abt.lz || framework_failure
cp "${f6b2_lz}" f6b.lz || framework_failure
cat "${f6b2_lz}" in > f6bt.lz || framework_failure
"${LZIPRECOVER}" -q --remove=d:t fox6t.lz f6abt.lz f6b.lz bad2t.lz f6bt.lz
[ $? = 2 ] || test_failed $LINENO
cat "${bad2_lz}" in | cmp bad2t.lz - || test_failed $LINENO
cat "${f6b1_lz}" in | cmp f6abt.lz - || test_failed $LINENO
cmp fox6.lz fox6t.lz || test_failed $LINENO
cmp fox5.lz f6b.lz || test_failed $LINENO
cmp fox5.lz f6bt.lz || test_failed $LINENO
rm -f fox6t.lz f6b.lz f6bt.lz f6abt.lz bad2t.lz fox5.lz out2 out4 ||
	framework_failure

printf "\ntesting trailing data..."

cat "${in_lz}" "${inD}" > int.lz || framework_failure
"${LZIPRECOVER}" --dump=tdata int.lz > out || test_failed $LINENO
cmp "${inD}" out || test_failed $LINENO
rm -f out || framework_failure
"${LZIPRECOVER}" --dump=tdat int.lz -o out || test_failed $LINENO
cmp "${inD}" out || test_failed $LINENO
cat fox6.lz "${inD}" > fox6t.lz || framework_failure
cat "${inD}" "${inD}" > inD2 || framework_failure
"${LZIPRECOVER}" --dump=tda int.lz fox6t.lz -f -o out || test_failed $LINENO
cmp inD2 out || test_failed $LINENO
rm -f inD2 || framework_failure
cat ingin.lz "${inD}" > ingint.lz || framework_failure
"${LZIPRECOVER}" -q --dump=td ingint.lz > /dev/null
[ $? = 2 ] || test_failed $LINENO
"${LZIPRECOVER}" -i --dump=t ingint.lz > out || test_failed $LINENO
cmp "${inD}" out || test_failed $LINENO

"${LZIPRECOVER}" --strip=tdata int.lz > out || test_failed $LINENO
cmp "${in_lz}" out || test_failed $LINENO
rm -f out || framework_failure
"${LZIPRECOVER}" --strip=tdata int.lz -o out || test_failed $LINENO
cmp "${in_lz}" out || test_failed $LINENO
"${LZIPRECOVER}" --strip=tdata fox6t.lz -f -o out || test_failed $LINENO
cmp fox6.lz out || test_failed $LINENO
"${LZIPRECOVER}" --strip=tdata int.lz int.lz -f -o out || test_failed $LINENO
cmp in2.lz out || test_failed $LINENO
rm -f in2.lz || framework_failure
"${LZIPRECOVER}" --strip=tdata int.lz fox6t.lz > out || test_failed $LINENO
cat "${in_lz}" fox6.lz | cmp out - || test_failed $LINENO
"${LZIPRECOVER}" -q --strip=tdata ingint.lz > out	# /dev/null returns 1 on OS/2
[ $? = 2 ] || test_failed $LINENO
"${LZIPRECOVER}" -i --strip=tdata ingint.lz > out || test_failed $LINENO
cmp ingin.lz out || test_failed $LINENO

"${LZIPRECOVER}" --remove=tdata int.lz fox6t.lz || test_failed $LINENO
cmp "${in_lz}" int.lz || test_failed $LINENO
cmp fox6.lz fox6t.lz || test_failed $LINENO
"${LZIPRECOVER}" --remove=tdata int.lz || test_failed $LINENO
cmp "${in_lz}" int.lz || test_failed $LINENO
"${LZIPRECOVER}" --remove=tdata fox6t.lz || test_failed $LINENO
cmp fox6.lz fox6t.lz || test_failed $LINENO
"${LZIPRECOVER}" -q --remove=tdata ingint.lz
[ $? = 2 ] || test_failed $LINENO
cmp -s ingin.lz ingint.lz && test_failed $LINENO
"${LZIPRECOVER}" -i --remove=tdata ingint.lz || test_failed $LINENO
cmp ingin.lz ingint.lz || test_failed $LINENO
rm -f int.lz fox6t.lz ingint.lz ingin.lz || framework_failure

for i in "${f6s3_lz}" "${f6s4_lz}" "${f6s5_lz}" "${f6s6_lz}" ; do
	"${LZIPRECOVER}" --strip=tdata "$i" > out || test_failed $LINENO "$i"
	"${LZIPRECOVER}" --dump=tdata "$i" > tdata || test_failed $LINENO "$i"
	cmp fox6.lz out || test_failed $LINENO "$i"
	cat out tdata | cmp "$i" - || test_failed $LINENO "$i"
	cat "$i" "${inD}" > f6t.lz || framework_failure
	"${LZIPRECOVER}" --strip=tdata f6t.lz > out || test_failed $LINENO "$i"
	"${LZIPRECOVER}" --dump=tdata f6t.lz > tdata || test_failed $LINENO "$i"
	cmp fox6.lz out || test_failed $LINENO "$i"
	cat out tdata | cmp f6t.lz - || test_failed $LINENO "$i"
	"${LZIPRECOVER}" --remove=tdata f6t.lz || test_failed $LINENO "$i"
	cmp fox6.lz f6t.lz || test_failed $LINENO "$i"
	rm -f out tdata f6t.lz || framework_failure
done

echo
if [ ${fail} = 0 ] ; then
	echo "tests completed successfully."
	cd "${objdir}" && rm -r tmp
else
	echo "tests failed."
fi
exit ${fail}
