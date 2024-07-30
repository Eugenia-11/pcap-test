CXX = g++
CXXFLAGS = -Wall -O2 -std=c++11
LDFLAGS = -lpcap -lnet

TARGET = pcap-test
SRCDIR = src
INCDIR = include

SRCS = $(wildcard $(SRCDIR)/*.cpp)
OBJS = $(SRCS:.cpp=.o)

$(TARGET): $(OBJS)
	$(CXX) -o $@ $^ $(LDFLAGS)

%.o: %.cpp
	$(CXX) $(CXXFLAGS) -I$(INCDIR) -c $< -o $@

clean:
	rm -f $(OBJS) $(TARGET)

