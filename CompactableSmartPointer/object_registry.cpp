#include "object_registry.h"

#include <cassert>

using namespace std;

namespace
{
  proposed_std::detail::object_registry g_ObjectRegistry;
}

namespace proposed_std
{
  namespace detail
  {
    object_registry::object_registry()
    : m_Registry(), m_Lock()
    {
      init_lock(m_Lock);
    }

    void object_registry::register_object(object_node_base& objNode) noexcept
    {
      assert(!objNode.is_linked());

      g_ObjectRegistry.m_Registry.insert(g_ObjectRegistry.m_Registry.end(), objNode);
    }

    void object_registry::deregister_object(const object_node_base& objNode) noexcept
    {
      assert(objNode.is_linked());

      g_ObjectRegistry.m_Registry.erase(g_ObjectRegistry.m_Registry.iterator_to(objNode));
    }

    lock_guard object_registry::acquire_lock() noexcept
    {
      return lock_guard(g_ObjectRegistry.m_Lock);
    }

  }  // namespace detail
}  // namespace proposed_std

