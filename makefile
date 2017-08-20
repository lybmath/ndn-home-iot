SDIR = src
ODIR = obj
CC = g++
CFLAGS := -std=c++11 `pkg-config --cflags libndn-cxx`
INC  = -I$(SDIR)
LIBS := `pkg-config --libs libndn-cxx`

MAKE_OBJ_DIR := $(shell mkdir -p $(ODIR))
SRC = $(notdir $(wildcard $(SDIR)/*.cpp))
OBJ := $(patsubst %.cpp, $(ODIR)/%.o, $(SRC))
DEPS = $(OBJ:.o=.cpp.d)

.INTERMEDIATE: $(OBJ)
.PRECIOUS: $(OBJ)

debug:
	@echo $(CFLAGS)
	@echo $(LIBS)

all: server.app device.app iotc.app
	@echo "@@@ make all @@@@"

server: server.app iotc.app
	@echo "@@@ compile server side @@@@"

iotc: iotc.app

device: device.app

%.app: %.cpp $(OBJ)
	$(CC) $(CFLAGS) $< $(OBJ) $(INC) $(LIBS) -o $@ 

$(ODIR)/%.o: $(SDIR)/%.cpp $(ODIR)/%.cpp.d
	$(CC) $(CFLAGS) -c $< $(INC) -o $@

$(DEPS): $(ODIR)/%.cpp.d: $(SDIR)/%.cpp
	$(CC) $(CFLAGS) $< -MM $(INC) > $<.d && mv $<.d $(ODIR)/

-include $(DEPS)

.PHONY: clean distclean

clean:
	@rm -rf *.app

distclean: clean
	@rm -rf $(ODIR)
