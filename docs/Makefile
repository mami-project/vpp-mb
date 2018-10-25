TEX = pdflatex -shell-escape -interaction=nonstopmode -file-line-error
PRE =  $(TEX) -ini -job-name="preamble" "&pdflatex preamble.tex\dump"
BIB = bibtex

.PHONY: all

all: user-guide.pdf

user-guide.pdf : user-guide.tex
	$(TEX) user-guide.tex
	$(TEX) user-guide.tex

clean:
	rm user-guide.aux user-guide.toc user-guide.out user-guide.log
