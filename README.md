# “Cryptographic algorithm implementation: AES cipher”
-	**The purpose of the practical task:** is to try to implement one of the cryptographic algorithms - **AES cipher**
-	The AES encryption algorithm defines multiple transformations that are performed on the data stored in an array. 

## AES Scheme
![[Pasted image 20220421144723.png]]

## Operations
1.	**DivideIntoBlocks**
		- The **DivideIntoBlocks** functons must perform the division of the input text into blocks of 128bit (16 bytes).
		- 
		- Each block is respresented as a 4x4 matrix
		 ![[Pasted image 20220421145718.png]]
		
2.	**GetRoundKeys**
		- The **GetRoundKeys** functions performs key deployment. Since AES implies the use of a 128-bit key, this means that for data of greater length, a key sequence must be generated that is equal to the length of the encrypted message.
		- 
		- For this purpose, the deployment function is used (a separate 128-bit key encryption key is generated for each encrypted block).
		 

3.	**AddRoundKey**
		- The **AddRoundKey** function adds a block to the **RoundKey** key (**XOR operation (**⊕**)**)
		- 
		![[Pasted image 20220421150634.png]]

4.	**SubBytes**
		- The **SubBytes** function is needed to perform the substitution : each byte in the block is replaced by the corresponding element from the fixed table 
		- (**S-box**).
		 ![[Pasted image 20220421152941.png]]
		- 
		![[Pasted image 20220421152229.png]]

5.	**MixColumns**
		- The **MixColumns** function consists of multiplying each column of the block with a constant matrix as follows:
		- 
		![[Pasted image 20220421153235.png]]