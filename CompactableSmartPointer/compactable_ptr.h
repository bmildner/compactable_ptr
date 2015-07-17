#ifndef PROPOSED_STD_COMPACTABLE_PTR_H
#define PROPOSED_STD_COMPACTABLE_PTR_H

#pragma once

#include <memory>
#include <mutex>

#include "object_registry.h"

namespace proposed_std
{
  namespace detail
  {

    template <typename T>
    class pointer_base
    {
      public:
        constexpr pointer_base() noexcept
        : m_Lock(), m_AccessProxyCount(0), m_pObjectNode(nullptr), m_PointerNode(*this)
        {
          detail::init_lock(m_Lock);  // is noexcept
        }

      protected:
        using count = std::size_t;

        using lock = detail::lock;
        using lock_guard = detail::lock_guard;

        using object_node  = detail::object_node<T>;
        using pointer_node = detail::pointer_node<T>;

        using size_type = typename object_node::size_type;

        // do not call while holding the lock as this may cause a dead-lock!
        void atomic_increment_access_proxy_count() const;
        void atomic_decrement_access_proxy_count() const;

        count get_access_proxy_count() const;

        lock_guard acquire_lock() const;

        size_type use_count() const noexcept
        {
          if (m_pObjectNode != nullptr)
          {
            return m_pObjectNode->use_count();
          }
          else
          {
            return 0;
          }
        }

        static void register_object(detail::object_node_base& objNode) noexcept;


        mutable lock  m_Lock;
        mutable count m_AccessProxyCount;

        object_node* m_pObjectNode;
        pointer_node m_PointerNode;
    };

    template <typename T>
    void pointer_base<T>::atomic_increment_access_proxy_count() const
    {
      lock_guard lock(m_Lock);

      m_AccessProxyCount++;
    }

    template <typename T>
    void pointer_base<T>::atomic_decrement_access_proxy_count() const
    {
      lock_guard lock(m_Lock);

      m_AccessProxyCount--;
    }

    template <typename T>
    typename pointer_base<T>::count pointer_base<T>::get_access_proxy_count() const
    {
      return m_AccessProxyCount;
    }

    template <typename T>
    typename pointer_base<T>::lock_guard pointer_base<T>::acquire_lock() const
    {
      return lock_guard(m_Lock);
    }

    template <typename T>
    void pointer_base<T>::register_object(detail::object_node_base& objNode) noexcept
    {
      lock_guard lock(detail::object_registry::acquire_lock());

      detail::object_registry::register_object(objNode);
    }

  }  // namespace detail

  // TODO: add make_compactable template function

  template <typename T>
  class access_proxy;

  template <typename T>
  class compactable_ptr : protected detail::pointer_base<T>
  {
    public:
      using base = pointer_base<T>;
      using element_type = T;
      using access_proxy = access_proxy<T>;
      using size_type = typename base::size_type;

      // constructors
      constexpr compactable_ptr() noexcept;
      template <class Y> 
      explicit compactable_ptr(Y* p);
      template <class Y, class D> 
      compactable_ptr(Y* p, D d);
      template <class Y, class D, class A> 
      compactable_ptr(Y* p, D d, A a);
      constexpr compactable_ptr(std::nullptr_t)  noexcept;
      template <class D> 
      compactable_ptr(std::nullptr_t p, D d);
      template <class D, class A> 
      compactable_ptr(std::nullptr_t p, D d, A a);
      template <class Y> 
      compactable_ptr(const compactable_ptr<Y>& r, T* p);  // aliasing constructor!  // diff to shared_ptr: noexcept
      compactable_ptr(const compactable_ptr& r) noexcept;
      template <class Y> 
      compactable_ptr(const compactable_ptr<Y>& r);  // diff to shared_ptr: noexcept
      compactable_ptr(compactable_ptr&& r) noexcept;
      template <class Y, class = typename std::enable_if<std::is_convertible<Y*, T*>::value>::type>  // Y* must be convertible to T* 
      compactable_ptr(compactable_ptr<Y>&& r); // diff to shared_ptr: noexcept
      //compactable_ptr(std::shared_ptr<T>&& r) noexcept;  // TODO: remove??
      //template <class Y>
      //compactable_ptr(std::shared_ptr<Y>&& r) noexcept;  // TODO: remove??
      //template <class Y> 
      //explicit compactable_ptr(const std::weak_ptr<Y>& r);  // TODO: remove??
      template <class Y, class D> 
      compactable_ptr(std::unique_ptr<Y, D>&& r);
//      : m_SharedPtr()
//      {}

      // destructor:
      ~compactable_ptr();

      // assignment:
      compactable_ptr& operator=(const compactable_ptr& r) noexcept;
      template <class Y> 
      compactable_ptr& operator=(const compactable_ptr<Y>& r) noexcept;
      compactable_ptr& operator=(compactable_ptr&& r) noexcept;
      template <class Y> 
      compactable_ptr& operator=(compactable_ptr<Y>&& r) noexcept;
      compactable_ptr& operator=(std::shared_ptr<T>&& r) noexcept;  // TODO: remove??
      template <class Y> 
      compactable_ptr& operator=(std::shared_ptr<Y>&& r) noexcept;  // TODO: remove??
      template <class Y, class D> 
      compactable_ptr& operator=(std::unique_ptr<Y, D>&& r);

      // modifiers:
      void swap(compactable_ptr& r) noexcept;
      void reset() noexcept;
      template <class Y> 
      void reset(Y* p);
      template <class Y, class D> 
      void reset(Y* p, D d);
      template <class Y, class D, class A> 
      void reset(Y* p, D d, A a);

      // observers:
      access_proxy get() const noexcept;
      access_proxy operator*() const noexcept;

      size_type use_count() const noexcept;
      bool unique() const noexcept;
      explicit operator bool() const noexcept;
      template <class U> 
      bool owner_before(std::shared_ptr<U> const& b) const;
      template <class U> 
      bool owner_before(std::weak_ptr<U> const& b) const;

    private:
      friend class ::proposed_std::access_proxy<T>;

      template <typename Y>
      friend class ::proposed_std::compactable_ptr;

      friend class ::proposed_std::detail::pointer_node_base;

  };

  // constructors
  template <typename T>
  constexpr compactable_ptr<T>::compactable_ptr() noexcept
  : base()
  {}

  template <typename T>
  template <class Y>
  compactable_ptr<T>::compactable_ptr(Y* p)
  : compactable_ptr()
  {
    // TODO: use allocator
    m_pObjectNode = new detail::object_node<T>(m_PointerNode, p);

    register_object(*m_pObjectNode);  // is noexcept
  }

  template <typename T>
  template <class Y, class D>
  compactable_ptr<T>::compactable_ptr(Y* p, D d)
  : compactable_ptr()
  {
    // TODO: use allocator
    m_pObjectNode = new detail::extended_object_node<T, Y, D>(m_PointerNode, p, p, d);

    register_object(*m_pObjectNode);  // is noexcept
  }

  template <typename T>
  template <class Y, class D, class A>
  compactable_ptr<T>::compactable_ptr(Y* p, D d, A a)
  : compactable_ptr()
  {
    using node_type    = detail::extended_object_node<T, Y, D, A>;
    using alloc_traits = std::allocator_traits<A>::rebind_traits<node_type>;

    std::allocator_traits<A>::rebind_alloc<node_type> alloc(a);

    // allocate memory and secure it in guard
    std::unique_ptr<node_type> guard_ptr(alloc_traits::allocate(alloc, 1));
    
    // construct node
    alloc_traits::construct(alloc, guard_ptr.get(), m_PointerNode, p, p, std::move(d), std::move(alloc));  // TODO: is that move(alloc) OK ???

    // release guard and get pointer
    m_pObjectNode = guard_ptr.release();

    register_object(*m_pObjectNode);  // is noexcept
  }

  template <typename T>
  constexpr compactable_ptr<T>::compactable_ptr(std::nullptr_t) noexcept
  : compactable_ptr()
  {}

  template <typename T>
  template <class D>
  compactable_ptr<T>::compactable_ptr(std::nullptr_t p, D d)
  : compactable_ptr()
  {
    // TODO: use allocator
    // we need to create a node to hold the deleter!
    m_pObjectNode = new detail::extended_object_node<T, T, D>(m_PointerNode, p, p, d);

    register_object(*m_pObjectNode);  // is noexcept
  }

  template <typename T>
  template <class D, class A>
  compactable_ptr<T>::compactable_ptr(std::nullptr_t p, D d, A a)
  : compactable_ptr()
  {
    using node_type = detail::extended_object_node<T, T, D, A>;
    using alloc_traits = std::allocator_traits<A>::rebind_traits<node_type>;

    std::allocator_traits<A>::rebind_alloc<node_type> alloc(a);

    // allocate memory and secure it in guard
    std::unique_ptr<node_type> guard_ptr(alloc_traits::allocate(alloc, 1));

    // construct node
    alloc_traits::construct(alloc, guard_ptr.get(), m_PointerNode, p, p, std::move(d), std::move(alloc));  // TODO: is that move(alloc) OK ???

    // release guard and get pointer
    m_pObjectNode = guard_ptr.release();

    register_object(*m_pObjectNode);  // is noexcept
  }

  template <typename T>
  template <class Y>
  compactable_ptr<T>::compactable_ptr(const compactable_ptr<Y>& r, T* p)  // noexcept
  : compactable_ptr()
  {    
    {
      // Rational for lock order: avoid deadlock in case someone locks the registry first and then tries to lock a pointer
      lock_guard registry_lock(detail::object_registry::acquire_lock());
      lock_guard other_lock(r.m_Lock);

      if (r.m_pObjectNode != nullptr)
      {
        // TODO: use allocator
        // create node that holds the original node and our pointer
        m_pObjectNode = new detail::aliasing_object_node<T, Y, typename compactable_ptr<Y>::Allocator>(m_PointerNode, p, *r.m_pObjectNode, r.m_Allocator);
      }
      else
      {
        // TODO: use allocator
        // create node that holds our pointer and a no-op deleter            // identity workaround for MSVC 2013
        m_pObjectNode = new detail::extended_object_node<T, T, decltype(detail::identity(&detail::EmptyDeleter<T>)), typename compactable_ptr<Y>::Allocator>(m_PointerNode, p, p, &detail::EmptyDeleter<T>, r.Allocator);  // TODO: noexcept vs. bad_alloc!!!
      }
    }

    register_object(*m_pObjectNode);  // is noexcept
  }

  template <typename T>
  compactable_ptr<T>::compactable_ptr(const compactable_ptr& r) noexcept
  : compactable_ptr()
  {
    // Rational for lock order: avoid deadlock in case someone locks the registry first and then tries to lock a pointer
    lock_guard registry_lock(detail::object_registry::acquire_lock());
    lock_guard other_lock(r.m_Lock);

    m_pObjectNode = r.m_pObjectNode;

    m_pObjectNode->add_pointer(m_PointerNode);
  }

  template <typename T>
  template <class Y, class>
  compactable_ptr<T>::compactable_ptr(compactable_ptr<Y>&& r)  // noexcept
  : compactable_ptr()
  {
    // Rational for lock order: avoid deadlock in case someone locks the registry first and then tries to lock a pointer
    lock_guard registry_lock(detail::object_registry::acquire_lock());
    lock_guard other_lock(r.m_Lock);

    static_assert(std::is_convertible<Y*, T*>::value, "Y* must be assignable to T*");

    if (r.m_pObjectNode != nullptr)
    {
      // TODO: use allocator
      // create node that holds the original node and our pointer
      m_pObjectNode = new detail::aliasing_object_node<T, Y, typename compactable_ptr<Y>::Allocator>(m_PointerNode, p, *r.m_pObjectNode, std::move(r.m_Allocator));
    }
    else
    {
      // TODO: use allocator!!!
      // create node that holds our pointer and a no-op deleter            // identity workaround for MSVC 2013
      m_pObjectNode = new detail::extended_object_node<T, T, decltype(detail::identity(&detail::EmptyDeleter<T>)), typename compactable_ptr<Y>::Allocator>(m_PointerNode, p, p, &detail::EmptyDeleter<T>, std::move(r.m_Allocator));
    }

    m_pObjectNode = r.m_pObjectNode;

    m_pObjectNode->add_pointer(m_PointerNode);

    assert(r.get_access_proxy_count() == 0);

    m_pObjectNode->remove_pointer(r.m_PointerNode);
    r.m_pObjectNode = nullptr;

    assert(!r);
  }


  // destructor
  template <typename T>
  compactable_ptr<T>::~compactable_ptr()
  {
    lock_guard lock(m_Lock);

    if (m_pObjectNode != nullptr)
    {
      lock_guard regirstry_lock(detail::object_registry::acquire_lock());

      if (m_pObjectNode->remove_pointer(m_PointerNode))  // is noexcept
      {
        detail::object_registry::deregister_object(*m_pObjectNode);  // is noexcept

        m_pObjectNode->delete_object();  // is noexcept

        m_pObjectNode->get_node_deleter()(m_pObjectNode);

//        detail::default_deleter<object_node<ManagedType>, Allocator>()(m_Allocator, m_pManagedNode);
        //delete m_pObjectNode;  // TODO: use allocator if set??
      }
    }

    assert(!m_PointerNode.is_linked());
  }


  // observers
  template <typename T>
  typename compactable_ptr<T>::size_type compactable_ptr<T>::use_count() const noexcept
  {
    return base::use_count();
  }

  template <typename T>
  bool compactable_ptr<T>::unique() const noexcept
  {
    return use_count() == 1;
  }


  template <typename T>
  class access_proxy
  {
    public:
      using compactable_ptr = compactable_ptr<T>;

      // constructors
      explicit access_proxy(const compactable_ptr& ptr);
      explicit access_proxy(compactable_ptr&& rhs);

      explicit access_proxy(const access_proxy& rhs);
      explicit access_proxy(access_proxy&& rhs);

      // detructor
      ~access_proxy();

      // assignment
      access_proxy& operator=(const access_proxy& rhs);
      access_proxy& operator=(access_proxy&& rhs);

      // observers
      T* get() const noexcept;
      T& operator*() const noexcept;
      T* operator->() const noexcept;

    private:
      compactable_ptr m_CompactablePtr;
  };

  // constructors
  template <typename T>
  access_proxy<T>::access_proxy(const compactable_ptr& ptr)
  : m_CompactablePtr(ptr)
  {
    m_CompactablePtr.atomic_increment_access_proxy_count();
  }

  template <typename T>
  access_proxy<T>::access_proxy(compactable_ptr&& rhs)
  : m_CompactablePtr(std::forward(rhs))
  {
    m_CompactablePtr.atomic_increment_access_proxy_count();
  }

  template <typename T>
  access_proxy<T>::access_proxy(const access_proxy& rhs)
  : m_CompactablePtr(rhs.m_CompactablePtr)
  {
    m_CompactablePtr.atomic_increment_access_proxy_count();
  }

  template <typename T>
  access_proxy<T>::access_proxy(access_proxy&& rhs)
  : m_CompactablePtr(std::move(rhs.m_CompactablePtr))
  {
  }

  // detructor
  template <typename T>
  access_proxy<T>::~access_proxy()
  {
    if (m_CompactablePtr)
    {
      m_CompactablePtr.atomic_decrement_access_proxy_count();
    }
  }

  // assignment
  template <typename T>
  access_proxy<T>& access_proxy<T>::operator=(const access_proxy& rhs)
  {
    if (m_CompactablePtr)
    {
      m_CompactablePtr.atomic_decrement_access_proxy_count();
    }

    m_CompactablePtr = rhs.m_CompactablePtr;
    m_CompactablePtr.atomic_increment_access_proxy_count();

    return *this;
  }

  template <typename T>
  access_proxy<T>& access_proxy<T>::operator=(access_proxy&& rhs)
  {
    if (m_CompactablePtr)
    {
      m_CompactablePtr.atomic_decrement_access_proxy_count();
    }

    m_CompactablePtr = std::move(rhs.m_CompactablePtr);

    return *this;
  }

  // observers
  template <typename T>
  T* access_proxy<T>::get() const noexcept
  {
    return m_CompactablePtr.m_pObjectNode->get();
  }

  template <typename T>
  T& access_proxy<T>::operator*() const noexcept
  {
    return *m_CompactablePtr.m_pObjectNode->get();
  }

  template <typename T>
  T* access_proxy<T>::operator->() const noexcept
  {
    return m_CompactablePtr.m_pObjectNode->get();
  }

}  // namespace proposed_std

#endif

