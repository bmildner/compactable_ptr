#ifndef PROPOSED_STD_OBJCET_REGISTRY_H
#define PROPOSED_STD_OBJCET_REGISTRY_H

#pragma once


#include <utility>
#include <atomic>
#include <thread>
#include <functional>
#include <type_traits>

// "inclusion guard" macros for boost headers, dreaded MSVC code analysis causes warnings in boost headers ...
# ifdef _MSC_VER
#  include <codeanalysis\warnings.h>

#  define BOOST_INCL_GUARD_BEGIN  __pragma(warning(push))                                 \
                                  __pragma(warning(disable: ALL_CODE_ANALYSIS_WARNINGS))

#  define BOOST_INCL_GUARD_END    __pragma(warning(pop))

# else
#  define BOOST_INCL_GUARD_BEGIN
#  define BOOST_INCL_GUARD_END
# endif

BOOST_INCL_GUARD_BEGIN
#include <boost/intrusive/list.hpp>
#include <boost/noncopyable.hpp>
BOOST_INCL_GUARD_END

#ifndef noexcept
/// Compatibility with non-clang compilers.
# ifndef __has_feature
#  define __has_feature(x) 0
# endif
// Detect whether the compiler supports C++11 noexcept exception specifications.
# if (defined(__GNUC__) && (__GNUC__ >= 4 && __GNUC_MINOR__ >= 7 ) && defined(__GXX_EXPERIMENTAL_CXX0X__))
// GCC 4.7 and following have noexcept
# elif defined(__clang__) && __has_feature(cxx_noexcept)
// Clang 3.0 and above have noexcept
# elif defined(_MSC_VER) && (_MSC_VER >= 1900)
// MSVC 2015 and above should have noexcept!?
# else
#  define noexcept throw()
# endif
#endif

#ifndef constexpr
# if defined(_MSC_VER) && (_MSC_VER >= 1900)
// MSVC 2015 and above should have constexpr!?
# else
#  define constexpr
# endif
#endif


namespace proposed_std
{
  template <typename T>
  class compactable_ptr;

  namespace detail
  {
    // workaround for MSVC2013 bug that causes a "C3555: incorrect argument to 'decltype'" error
    template <typename T>
    T identity(T);


    using lock = std::atomic_flag;

    inline void init_lock(lock& l) noexcept
    {
      atomic_flag_clear(&l);
    }

    class lock_guard
    {
      public:
        inline lock_guard(lock& lock)
        : m_Lock(lock), m_Empty(false)
        {
          while (atomic_flag_test_and_set(&m_Lock))
          {
            std::this_thread::yield();
          }
        }

        inline lock_guard(lock_guard&& rhs)
        : m_Lock(rhs.m_Lock), m_Empty(false)
        {
          rhs.m_Empty = true;
        }

        inline ~lock_guard()
        {
          if (!m_Empty)
          {
            atomic_flag_clear(&m_Lock);
          }
        }

        lock_guard(const lock_guard& rhs) = delete;
        lock_guard& operator=(const lock_guard& rhs) = delete;
        lock_guard& operator=(lock_guard&& rhs) = delete;

    private:
        lock& m_Lock;
        bool  m_Empty;
    };


    using object_hook  = boost::intrusive::list_base_hook<boost::intrusive::link_mode<boost::intrusive::safe_link>>;
    using pointer_hook = boost::intrusive::list_base_hook<boost::intrusive::link_mode<boost::intrusive::safe_link>>;

    class pointer_node_base : public pointer_hook
    {
      public:
        virtual ~pointer_node_base() = default;

        template <typename T>
        static bool is_same_pointer(const compactable_ptr<T>& ptr, const pointer_node_base& pointer_node) noexcept
        {
          return &pointer_node == &ptr.m_PointerNode;
        }

      private:
    };

    template <typename T>
    class pointer_node : public pointer_node_base
    {
      public:
        using compactable_ptr = ::proposed_std::compactable_ptr<T>;

        explicit pointer_node(compactable_ptr& ptr)  noexcept
        : m_Pointer(ptr)
        {}

        virtual ~pointer_node() override = default;

        compactable_ptr& get() const noexcept
        {
          return m_Pointer;
        }

      private:
        compactable_ptr& m_Pointer;
    };

    template <typename T>
    class mutable_pointer_node : public pointer_node_base
    {
      public:
        using compactable_ptr = ::proposed_std::compactable_ptr<T>;

        explicit mutable_pointer_node(compactable_ptr& ptr)  noexcept
        : m_pPointer(&ptr)
        {}

        virtual ~mutable_pointer_node() override = default;

        compactable_ptr& get() const noexcept
        {
          return *m_Pointer;
        }

        compactable_ptr* reset(compactable_ptr& newPtr) noexcept
        {
          compactable_ptr* old = m_pPointer;

          m_pPointer = &newPtr;

          return old;
        }

        bool is_same_pointer(const pointer_node_base& pointer_node) const noexcept
        {
          return pointer_node_base::is_same_pointer(*m_pPointer, pointer_node);
        }

      private:
        compactable_ptr* m_pPointer;
    };


    template <typename T, typename Alloc = void>
    struct DefaultDeleter
    {
      void operator()(Alloc& a, T* ptr) noexcept
      {
        if (ptr != nullptr)
        {
          using alloc_traits = std::allocator_traits<Alloc>::rebind_traits<T>;

          std::allocator_traits<Alloc>::rebind_alloc<T> alloc(a);

          // destroy object
          alloc_traits::destroy(alloc, ptr);

          // deallocate memory
          alloc_traits::deallocate(alloc, ptr, 1);
        }
      }
    };

    template <typename T>
    struct DefaultDeleter<T, void>
    {
      void operator()(T* ptr) noexcept
      {
        delete ptr;
      }
    };

    template <typename T>
    void EmptyDeleter(T*)
    {}

    template <typename T>
    using DefaultAllocator = std::allocator<T>;


    class object_node_base : public object_hook, private boost::noncopyable
    {
      public:
        explicit object_node_base(pointer_node_base& pointer_node) noexcept
        : m_Pointers()
        {
          m_Pointers.insert(m_Pointers.end(), pointer_node);
        }

        virtual ~object_node_base()
        {
          assert(m_Pointers.empty());
        }

        virtual void add_pointer(pointer_node_base& pointer_node) noexcept
        {
          assert(!pointer_node.is_linked());

          m_Pointers.insert(m_Pointers.end(), pointer_node);
        }

        // returns true if the last pointer has been removed
        virtual bool remove_pointer(pointer_node_base& pointer_node) noexcept
        {
          assert(pointer_node.is_linked());

          m_Pointers.erase(m_Pointers.iterator_to(pointer_node));

          return m_Pointers.empty();
        }

        virtual void delete_object() noexcept = 0;

      protected:
        using pointers = boost::intrusive::list<pointer_node_base, boost::intrusive::base_hook<pointer_hook>, boost::intrusive::constant_time_size<false>>;

        pointers m_Pointers;
    };

    template <typename T>
    class object_node : public object_node_base
    {
      public:
        object_node(pointer_node_base& pointer_node, T* ptr) noexcept
        : object_node_base(pointer_node), m_Pointer(ptr)
        {}

        virtual ~object_node() override
        {
          assert(m_Pointer == nullptr);
        }

        T* get() const noexcept
        {
          return m_Pointer;
        }

        virtual void delete_object() noexcept override
        {
          DefaultDeleter<T>()(m_Pointer);  // is noexcept

          assert((m_Pointer = nullptr) == nullptr);
        }

      protected:
        T* m_Pointer;
    };

    template <typename T, typename ManagedType, typename Deleter = DefaultDeleter<ManagedType>, typename Allocator = DefaultAllocator<ManagedType>>
    class extended_object_node : public object_node<T>
    {
      public:
        extended_object_node(pointer_node_base& pointer_node, T* ptr, ManagedType* managedPtr, Deleter deleter = Deleter(), Allocator allocator = Allocator()) noexcept
        : object_node(pointer_node, ptr), m_ManagedPtr(managedPtr), m_Deleter(std::move(deleter)), m_Allocator(std::move(allocator))
        {}

        virtual void delete_object() noexcept override
        {
#pragma warning (push)
#pragma warning (disable : 4127)  // no need for a warning that the conditional expression is constant ...
          // use allocator (via DefaultDeleter specialization) as deleter if the default deleter is present and the allocator is not the default allocator
          if (std::is_same<Deleter, DefaultDeleter<ManagedType>>::value && !std::is_same<Allocator, DefaultAllocator<ManagedType>>::value)
#pragma warning (pop)
          {
            DefaultDeleter<ManagedType, Allocator>()(m_Allocator, m_ManagedPtr);
          }
          else
          {
            m_Deleter(m_ManagedPtr);
          }

          assert((m_ManagedPtr = nullptr) == nullptr);
          assert((m_Pointer = nullptr) == nullptr);
        }

      private:
        ManagedType* m_ManagedPtr;
        Deleter      m_Deleter;
        Allocator    m_Allocator;
    };

    template <typename T, typename ManagedType>                          // identity workaround for MSVC 2013
    class aliasing_object_node : public extended_object_node<T, T, decltype(identity(&EmptyDeleter<T>))>
    {
      public:
        aliasing_object_node(pointer_node<T>& pointer_node, T* ptr, object_node<ManagedType>& managedNode) noexcept
        : extended_object_node(pointer_node, ptr, ptr, EmptyDeleter<T>), m_pManagedNode(&managedNode), m_BlockerNode(pointer_node.get())
        {
          assert(m_pManagedNode != nullptr);

          // add blocker node to managed node
          m_pManagedNode->add_pointer(m_BlockerNode);
        }

        virtual void add_pointer(pointer_node_base& pointer_node) noexcept
        {
          assert(!pointer_node.is_linked());

          m_Pointers.insert(m_Pointers.end(), pointer_node);
        }

        // if the last pointer has been removed it returns true and removes the blocker node, destroys managed object and node if no pointers left in it
        virtual bool remove_pointer(pointer_node_base& pointer_node) noexcept
        {
          assert(pointer_node.is_linked());
          assert(m_BlockerNode.is_linked());

          m_Pointers.erase(m_Pointers.iterator_to(pointer_node));

          if (m_Pointers.empty())
          {
            assert(m_pManagedNode != nullptr);

            // remove blocker node from managed node
            if (m_pManagedNode->remove_pointer(m_BlockerNode))
            {
              detail::object_registry::deregister_object(*m_pManagedNode);  // is noexcept

              m_pManagedNode->delete_object();  // is noexcept

              delete m_pManagedNode;  // TODO: use allocator if set??
            }

            assert(!m_BlockerNode.is_linked());
          }
          else
          {
            assert(!m_Pointers.empty());

            if (m_BlockerNode.is_same_pointer(pointer_node))
            {
              m_BlockerNode.reset(m_Pointers.begin()->get());
            }

            assert(!m_BlockerNode.is_same_pointer(pointer_node));
          }

          assert(pointer_node.is_linked());

          return m_Pointers.empty();
        }

        virtual void delete_object() noexcept override
        {
          // do not delete our object, only the object in the managed node may be deleted!
          assert((m_Pointer = nullptr) == nullptr);
        }

      private:
        object_node<ManagedType>* m_pManagedNode;
        mutable_pointer_node<T>   m_BlockerNode;
    };


    class object_registry : private boost::noncopyable
    {
      public:
        object_registry();

        // acquire lock first!
        static void register_object(object_node_base& objNode)  noexcept;
        // acquire lock first!
        static void deregister_object(const object_node_base& objNode)  noexcept;

        static lock_guard acquire_lock() noexcept;

      private:
        using objects = boost::intrusive::list<object_node_base, boost::intrusive::base_hook<object_hook>, boost::intrusive::constant_time_size<false>>;

        objects m_Registry;
        lock    m_Lock;
    };

  }
}

#endif
