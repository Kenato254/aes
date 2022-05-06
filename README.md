### “Cryptographic algorithm implementation: AES cipher”
-	**The purpose of the practical task:** is to try to implement one of the cryptographic algorithms - **AES cipher**
-	The AES encryption algorithm defines multiple transformations that are performed on the data stored in an array. 

## AES Scheme
![[Pasted image 20220421144723.png]]

## Main Functions
1.	**DivideIntoBlocks**
		- The **DivideIntoBlocks** functons must perform the division of the input text into blocks of 128bit (16 bytes).
		- 
		- Each block is respresented as a 4x4 matrix
		 ![[Pasted Images/20220421145718.png]]
		
2.	**GetRoundKeys**
		- The **GetRoundKeys** functions performs key deployment. Since AES implies the use of a 128-bit key, this means that for data of greater length, a key sequence must be generated that is equal to the length of the encrypted message.
		- 
		- For this purpose, the deployment function is used (a separate 128-bit key encryption key is generated for each encrypted block).
		 

3.	**AddRoundKey**
		- The **AddRoundKey** function adds a block to the **RoundKey** key (**XOR operation (**⊕**)**)
		- 
		![[Pasted Images/20220421150634.png]]

4.	**SubBytes**
		- The **SubBytes** function is needed to perform the substitution : each byte in the block is replaced by the corresponding element from the fixed table 
		- (**S-box**).

		![[Pasted Images/20220421152941.png]]
		- 
		![[Pasted Images/20220421152229.png]]

5.	**ShiftRows** 
		- The ShiftRows function cyclically shifts the bytes in each row of the block by r bytes to the left, depending on the row number.
		![[Pasted ./Images/image.jpg]]

6.	**MixColumns**
		- The **MixColumns** function consists of multiplying each column of the block with a constant matrix as follows:
		- 
		![[Pasted image 20220421153235.png]]

## Helper Functions
1. **SubWord**
	- The **SubWord** Function used in the Key Expansion routine that takes a four-byte input word and applies an S-box to each of the four bytes to produce an output word.

2. **RotWord**
	- The **RotWord** Function used in the Key Expansion routine that takes a four-byte word and performs a cyclic permutation. 

3. **RCon**
	- The **RCon** Function runs a given word through a XOR operation against a round constant (Round Coefficient).


