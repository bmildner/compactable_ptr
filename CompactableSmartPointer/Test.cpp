#include <memory>

#include "compactable_ptr.h"

using namespace std;
using namespace proposed_std;

template <typename T>
void DeleteFkt(T* ptr)
{
  delete ptr;
}

template <class Tp>
struct SimpleAllocator 
{
  typedef Tp value_type;

  SimpleAllocator(/*ctor args*/) {}

  template <class T> 
  SimpleAllocator(const SimpleAllocator<T>&) {}

  Tp* allocate(std::size_t n)
  {
    return std::allocator<Tp>().allocate(n);
  }
  void deallocate(Tp* p, std::size_t n)
  {
    std::allocator<Tp>().deallocate(p, n);
  }
};

template <class T, class U>
bool operator==(const SimpleAllocator<T>&, const SimpleAllocator<U>&);

template <class T, class U>
bool operator!=(const SimpleAllocator<T>&, const SimpleAllocator<U>&);


template class compactable_ptr<int>;
template class compactable_ptr<double>;
template class compactable_ptr<std::wstring>;

int main()
{
  struct A { int m_Int; };
  struct B : A {};

  {
    // c'tors

    compactable_ptr<int> int_ptr(new int(4711));

    compactable_ptr<float> float_ptr;

    compactable_ptr<A> a1_ptr(new B, [](B* ptr) -> void { delete ptr; });
    compactable_ptr<A> a2_ptr(new B, [](A* ptr) -> void { delete ptr; });
    compactable_ptr<A> a3_ptr(new B, DeleteFkt<B>);
    compactable_ptr<A> a4_ptr(new B, DeleteFkt<A>);

    compactable_ptr<A> a5_ptr(new B, [](B* ptr) -> void { delete ptr; }, SimpleAllocator<long long>());
    compactable_ptr<A> a6_ptr(new B, [](A* ptr) -> void { delete ptr; }, SimpleAllocator<double>());
    compactable_ptr<A> a7_ptr(new B, DeleteFkt<B>, SimpleAllocator<long long>());
    compactable_ptr<A> a8_ptr(new B, DeleteFkt<A>, SimpleAllocator<double>());

    compactable_ptr<char> c1_ptr(0);
    compactable_ptr<char> c2_ptr(nullptr);

    compactable_ptr<char> c3_ptr(nullptr, DeleteFkt<char>);

    compactable_ptr<char> c4_ptr(nullptr, DeleteFkt<char>, SimpleAllocator<double>());

    //compactable_ptr<int> i1_ptr(compactable_ptr<A>(new A), nullptr);

    //compactable_ptr<int> i2_ptr(compactable_ptr<int>(new int));

    //compactable_ptr<A> a9_ptr(compactable_ptr<B>(new B, DeleteFkt<B>));
  }

  shared_ptr<A> a1_ptr(new B, [](B* ptr) -> void { delete ptr; });
  shared_ptr<A> a2_ptr(shared_ptr<B>(new B));

  {
    compactable_ptr<A> a8_ptr(new B, DeleteFkt<A>, SimpleAllocator<double>());
  }

  return 0;
}
