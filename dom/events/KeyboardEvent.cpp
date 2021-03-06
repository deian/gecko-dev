/* -*- Mode: C++; tab-width: 2; indent-tabs-mode: nil; c-basic-offset: 2 -*- */
/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#include "mozilla/dom/KeyboardEvent.h"
#include "mozilla/TextEvents.h"
#include "prtime.h"

namespace mozilla {
namespace dom {

KeyboardEvent::KeyboardEvent(EventTarget* aOwner,
                             nsPresContext* aPresContext,
                             WidgetKeyboardEvent* aEvent)
  : UIEvent(aOwner, aPresContext,
            aEvent ? aEvent : new WidgetKeyboardEvent(false, 0, nullptr))
  , mInitializedByCtor(false)
  , mInitialzedWhichValue(0)
{
  NS_ASSERTION(mEvent->eventStructType == NS_KEY_EVENT, "event type mismatch");

  if (aEvent) {
    mEventIsInternal = false;
  }
  else {
    mEventIsInternal = true;
    mEvent->time = PR_Now();
    mEvent->AsKeyboardEvent()->mKeyNameIndex = KEY_NAME_INDEX_USE_STRING;
  }
}

NS_IMPL_ADDREF_INHERITED(KeyboardEvent, UIEvent)
NS_IMPL_RELEASE_INHERITED(KeyboardEvent, UIEvent)

NS_INTERFACE_MAP_BEGIN(KeyboardEvent)
  NS_INTERFACE_MAP_ENTRY(nsIDOMKeyEvent)
NS_INTERFACE_MAP_END_INHERITING(UIEvent)

bool
KeyboardEvent::AltKey()
{
  return mEvent->AsKeyboardEvent()->IsAlt();
}

NS_IMETHODIMP
KeyboardEvent::GetAltKey(bool* aIsDown)
{
  NS_ENSURE_ARG_POINTER(aIsDown);
  *aIsDown = AltKey();
  return NS_OK;
}

bool
KeyboardEvent::CtrlKey()
{
  return mEvent->AsKeyboardEvent()->IsControl();
}

NS_IMETHODIMP
KeyboardEvent::GetCtrlKey(bool* aIsDown)
{
  NS_ENSURE_ARG_POINTER(aIsDown);
  *aIsDown = CtrlKey();
  return NS_OK;
}

bool
KeyboardEvent::ShiftKey()
{
  return mEvent->AsKeyboardEvent()->IsShift();
}

NS_IMETHODIMP
KeyboardEvent::GetShiftKey(bool* aIsDown)
{
  NS_ENSURE_ARG_POINTER(aIsDown);
  *aIsDown = ShiftKey();
  return NS_OK;
}

bool
KeyboardEvent::MetaKey()
{
  return mEvent->AsKeyboardEvent()->IsMeta();
}

NS_IMETHODIMP
KeyboardEvent::GetMetaKey(bool* aIsDown)
{
  NS_ENSURE_ARG_POINTER(aIsDown);
  *aIsDown = MetaKey();
  return NS_OK;
}

bool
KeyboardEvent::Repeat()
{
  return mEvent->AsKeyboardEvent()->mIsRepeat;
}

NS_IMETHODIMP
KeyboardEvent::GetRepeat(bool* aIsRepeat)
{
  NS_ENSURE_ARG_POINTER(aIsRepeat);
  *aIsRepeat = Repeat();
  return NS_OK;
}

bool
KeyboardEvent::IsComposing()
{
  return mEvent->AsKeyboardEvent()->mIsComposing;
}

NS_IMETHODIMP
KeyboardEvent::GetModifierState(const nsAString& aKey,
                                bool* aState)
{
  NS_ENSURE_ARG_POINTER(aState);

  *aState = GetModifierState(aKey);
  return NS_OK;
}

NS_IMETHODIMP
KeyboardEvent::GetKey(nsAString& aKeyName)
{
  mEvent->AsKeyboardEvent()->GetDOMKeyName(aKeyName);
  return NS_OK;
}

NS_IMETHODIMP
KeyboardEvent::GetCharCode(uint32_t* aCharCode)
{
  NS_ENSURE_ARG_POINTER(aCharCode);
  *aCharCode = CharCode();
  return NS_OK;
}

uint32_t
KeyboardEvent::CharCode()
{
  // If this event is initialized with ctor, we shouldn't check event type.
  if (mInitializedByCtor) {
    return mEvent->AsKeyboardEvent()->charCode;
  }

  switch (mEvent->message) {
  case NS_KEY_UP:
  case NS_KEY_DOWN:
    return 0;
  case NS_KEY_PRESS:
    return mEvent->AsKeyboardEvent()->charCode;
  }
  return 0;
}

NS_IMETHODIMP
KeyboardEvent::GetKeyCode(uint32_t* aKeyCode)
{
  NS_ENSURE_ARG_POINTER(aKeyCode);
  *aKeyCode = KeyCode();
  return NS_OK;
}

uint32_t
KeyboardEvent::KeyCode()
{
  // If this event is initialized with ctor, we shouldn't check event type.
  if (mInitializedByCtor) {
    return mEvent->AsKeyboardEvent()->keyCode;
  }

  switch (mEvent->message) {
  case NS_KEY_UP:
  case NS_KEY_PRESS:
  case NS_KEY_DOWN:
    return mEvent->AsKeyboardEvent()->keyCode;
  }
  return 0;
}

uint32_t
KeyboardEvent::Which()
{
  // If this event is initialized with ctor, which can have independent value.
  if (mInitializedByCtor) {
    return mInitialzedWhichValue;
  }

  switch (mEvent->message) {
    case NS_KEY_UP:
    case NS_KEY_DOWN:
      return KeyCode();
    case NS_KEY_PRESS:
      //Special case for 4xp bug 62878.  Try to make value of which
      //more closely mirror the values that 4.x gave for RETURN and BACKSPACE
      {
        uint32_t keyCode = mEvent->AsKeyboardEvent()->keyCode;
        if (keyCode == NS_VK_RETURN || keyCode == NS_VK_BACK) {
          return keyCode;
        }
        return CharCode();
      }
  }

  return 0;
}

NS_IMETHODIMP
KeyboardEvent::GetLocation(uint32_t* aLocation)
{
  NS_ENSURE_ARG_POINTER(aLocation);

  *aLocation = Location();
  return NS_OK;
}

uint32_t
KeyboardEvent::Location()
{
  return mEvent->AsKeyboardEvent()->location;
}

// static
already_AddRefed<KeyboardEvent>
KeyboardEvent::Constructor(const GlobalObject& aGlobal,
                           const nsAString& aType,
                           const KeyboardEventInit& aParam,
                           ErrorResult& aRv)
{
  nsCOMPtr<EventTarget> target = do_QueryInterface(aGlobal.GetAsSupports());
  nsRefPtr<KeyboardEvent> newEvent =
    new KeyboardEvent(target, nullptr, nullptr);
  bool trusted = newEvent->Init(target);
  aRv = newEvent->InitKeyEvent(aType, aParam.mBubbles, aParam.mCancelable,
                               aParam.mView, aParam.mCtrlKey, aParam.mAltKey,
                               aParam.mShiftKey, aParam.mMetaKey,
                               aParam.mKeyCode, aParam.mCharCode);
  newEvent->SetTrusted(trusted);
  newEvent->mDetail = aParam.mDetail;
  newEvent->mInitializedByCtor = true;
  newEvent->mInitialzedWhichValue = aParam.mWhich;

  WidgetKeyboardEvent* internalEvent = newEvent->mEvent->AsKeyboardEvent();
  internalEvent->location = aParam.mLocation;
  internalEvent->mIsRepeat = aParam.mRepeat;
  internalEvent->mIsComposing = aParam.mIsComposing;
  internalEvent->mKeyNameIndex = KEY_NAME_INDEX_USE_STRING;
  internalEvent->mKeyValue = aParam.mKey;

  return newEvent.forget();
}

NS_IMETHODIMP
KeyboardEvent::InitKeyEvent(const nsAString& aType,
                            bool aCanBubble,
                            bool aCancelable,
                            nsIDOMWindow* aView,
                            bool aCtrlKey,
                            bool aAltKey,
                            bool aShiftKey,
                            bool aMetaKey,
                            uint32_t aKeyCode,
                            uint32_t aCharCode)
{
  nsresult rv = UIEvent::InitUIEvent(aType, aCanBubble, aCancelable, aView, 0);
  NS_ENSURE_SUCCESS(rv, rv);

  WidgetKeyboardEvent* keyEvent = mEvent->AsKeyboardEvent();
  keyEvent->InitBasicModifiers(aCtrlKey, aAltKey, aShiftKey, aMetaKey);
  keyEvent->keyCode = aKeyCode;
  keyEvent->charCode = aCharCode;

  return NS_OK;
}

void
KeyboardEvent::InitKeyboardEvent(const nsAString& aType,
                                 bool aCanBubble,
                                 bool aCancelable,
                                 nsIDOMWindow* aView,
                                 uint32_t aDetail,
                                 const nsAString& aKey,
                                 uint32_t aLocation,
                                 const nsAString& aModifiersList,
                                 bool aRepeat,
                                 ErrorResult& aRv)
{
  aRv = UIEvent::InitUIEvent(aType, aCanBubble, aCancelable, aView, aDetail);

  WidgetKeyboardEvent* keyEvent = mEvent->AsKeyboardEvent();
  keyEvent->modifiers = UIEvent::ComputeModifierState(aModifiersList);
  keyEvent->location = aLocation;
  keyEvent->mIsRepeat = aRepeat;
  keyEvent->mKeyNameIndex = KEY_NAME_INDEX_USE_STRING;
  keyEvent->mKeyValue = aKey;
}

} // namespace dom
} // namespace mozilla

using namespace mozilla;
using namespace mozilla::dom;

nsresult
NS_NewDOMKeyboardEvent(nsIDOMEvent** aInstancePtrResult,
                       EventTarget* aOwner,
                       nsPresContext* aPresContext,
                       WidgetKeyboardEvent* aEvent)
{
  KeyboardEvent* it = new KeyboardEvent(aOwner, aPresContext, aEvent);
  NS_ADDREF(it);
  *aInstancePtrResult = static_cast<Event*>(it);
  return NS_OK;
}
