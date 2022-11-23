CXX=g++-11.3
XLOGINXX=xbedna73

OBJ=kry.cpp
BIN=kry

CXXFLAGS:=-Wall -Wextra -Wsuggest-override -Wnull-dereference -Wshadow -Wold-style-cast -pedantic -lgmp -std=c++20

LINK.o = $(LINK.cpp)

all: CXXFLAGS += -Ofast -march=native -flto
all: kry

debug: CXXFLAGS += -g3 -fsanitize=address,undefined -fno-omit-frame-pointer
debug: kry

kry: $(OBJ)
	$(CXX) $(CXXFLAGS) $(LDFLAGS) $(OBJ) -o $(BIN)

pack:
	zip -r $(XLOGINXX).zip $(OBJ) Makefile doc.pdf doc/*

clean:
	rm -f $(BIN) $(XLOGINXX).zip

dep:
	g++ *.cpp -MM >> Makefile
