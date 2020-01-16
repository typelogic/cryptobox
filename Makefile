run: SealedBoxUtility.class
	@java -cp $(shell find libs/ -type f|tr '\n' ':') SealedBoxUtility

SealedBoxUtility.class: SealedBoxUtility.java
	@javac -cp $(shell find libs/ -type f|tr '\n' ':') SealedBoxUtility.java

clean: 
	@rm -f *.class

.PHONY: clean
