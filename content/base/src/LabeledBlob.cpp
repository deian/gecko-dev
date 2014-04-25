/* -*- Mode: C++; tab-width: 2; indent-tabs-mode: nil; c-basic-offset: 2 -*- */
/* vim:set ts=2 sw=2 sts=2 et cindent: */
/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#include "LabeledBlob.h"
#include "mozilla/dom/LabeledBlobBinding.h"
#include "LabeledBlobService.h"
#include "nsContentUtils.h"
#include "mozilla/dom/Sandbox.h"
#include "StructuredCloneTags.h"
#include "xpcprivate.h"

namespace mozilla {
namespace dom {

NS_IMPL_CYCLE_COLLECTION_WRAPPERCACHE_0(LabeledBlob)
NS_IMPL_CYCLE_COLLECTING_ADDREF(LabeledBlob)
NS_IMPL_CYCLE_COLLECTING_RELEASE(LabeledBlob)
NS_INTERFACE_MAP_BEGIN_CYCLE_COLLECTION(LabeledBlob)
  NS_WRAPPERCACHE_INTERFACE_MAP_ENTRY
  NS_INTERFACE_MAP_ENTRY(nsISupports)
NS_INTERFACE_MAP_END

LabeledBlob::LabeledBlob(nsIDOMBlob* blob, 
                         mozilla::dom::Label& privacy, mozilla::dom::Label& trust)
  : mPrivacy(&privacy)
  , mTrust(&trust)
  , mBlob(blob)
{
  SetIsDOMBinding();
}

already_AddRefed<LabeledBlob> 
LabeledBlob::Constructor(const GlobalObject& global, 
                         JSContext* cx,
                         nsIDOMBlob* blob,
                         ErrorResult& aRv)
{
  aRv.MightThrowJSException();
  Sandbox::EnableSandbox(global, cx);

  nsRefPtr<Label> privacy = Sandbox::GetPrivacyLabel(global, cx);
  if (!privacy) {
    JSErrorResult(cx, aRv, "Failed to get current trust label.");
    return nullptr;
  }

  nsRefPtr<Label> trust = Sandbox::GetTrustLabel(global, cx);
  if (!trust) {
    JSErrorResult(cx, aRv, "Failed to get current trust label.");
    return nullptr;
  }
  return Constructor(global, cx, blob, *privacy, *trust, aRv);
}

already_AddRefed<LabeledBlob> 
LabeledBlob::Constructor(const GlobalObject& global,
                         JSContext* cx,
                         nsIDOMBlob* blob,
                         mozilla::dom::Label& privacy, ErrorResult& aRv)
{
  aRv.MightThrowJSException();
  Sandbox::EnableSandbox(global, cx);

  nsRefPtr<Label> trust = Sandbox::GetTrustLabel(global, cx);
  if (!trust) {
    JSErrorResult(cx, aRv, "Failed to get current trust label.");
    return nullptr;
  }
  return Constructor(global, cx, blob, privacy, *trust, aRv);
}

already_AddRefed<LabeledBlob> 
LabeledBlob::Constructor(const GlobalObject& global,
                         JSContext* cx,
                         nsIDOMBlob* blob,
                         mozilla::dom::Label& privacy,
                         mozilla::dom::Label& trust, ErrorResult& aRv)
{
  JSCompartment *compartment = js::GetContextCompartment(cx);
  MOZ_ASSERT(compartment);

  if (MOZ_UNLIKELY(!xpc::sandbox::IsCompartmentSandboxed(compartment)))
    xpc::sandbox::EnableCompartmentSandbox(compartment);

  nsRefPtr<Label> privs = xpc::sandbox::GetCompartmentPrivileges(compartment);

  // current compartment label must flow to label of blob
  if (!xpc::sandbox::GuardWrite(compartment, privacy, trust, privs)) {
    JSErrorResult(cx, aRv, 
        "Label of blob is not above current label or below current clearance.");
    return nullptr;
  }

  // Create bloc

  nsRefPtr<Label> privacyCopy = privacy.Clone(aRv);
  if (aRv.Failed()) {
    return nullptr;
  }
  nsRefPtr<Label> trustCopy = trust.Clone(aRv);
  if (aRv.Failed()) {
    return nullptr;
  }

  nsRefPtr<LabeledBlob> labeledBlob = new LabeledBlob(blob, privacy, trust);

  if (aRv.Failed()) {
    return nullptr;
  }

  return labeledBlob.forget();
}

already_AddRefed<Label> 
LabeledBlob::Privacy() const
{
  nsRefPtr<Label> privacy = mPrivacy;
  return privacy.forget();
}

already_AddRefed<Label> 
LabeledBlob::Trust() const
{
  nsRefPtr<Label> trust = mTrust;
  return trust.forget();
}

already_AddRefed<nsIDOMBlob> 
LabeledBlob::GetBlob(JSContext* cx, ErrorResult& aRv) const
{
  JSCompartment *compartment = js::GetContextCompartment(cx);
  MOZ_ASSERT(compartment);

  if (MOZ_UNLIKELY(!xpc::sandbox::IsCompartmentSandboxed(compartment)))
    xpc::sandbox::EnableCompartmentSandbox(compartment);

  nsRefPtr<Label> privs = xpc::sandbox::GetCompartmentPrivileges(compartment);

  // current compartment label must flow to label of sandbox, raise it if need be
  if (!xpc::sandbox::GuardRead(compartment, *mPrivacy,*mTrust,
                               privs, cx, true)) {
    JSErrorResult(cx, aRv, "Cannot inspect blob.");
    return nullptr;
  }

  nsCOMPtr<nsIDOMBlob> blob = mBlob;
  return blob.forget();
}

already_AddRefed<nsIDOMBlob> 
LabeledBlob::Blob() const
{
  nsCOMPtr<nsIDOMBlob> blob = mBlob;
  return blob.forget();
}

bool
LabeledBlob::WriteStructuredClone(JSContext* cx, 
                                  JSStructuredCloneWriter* writer) 
{
  nsresult rv;
  nsCOMPtr<LabeledBlobService> lbs = 
    do_GetService("@mozilla.org/labeledblob-service;1", &rv);
  if (NS_FAILED(rv)) {
    return false;
  }
  if (JS_WriteUint32Pair(writer, SCTAG_DOM_LABELEDBLOB, 
                                 lbs->mLabeledBlobList.Length())) {
    lbs->mLabeledBlobList.AppendElement(this);
    return true;
  }
  return false;
}

JSObject*
LabeledBlob::ReadStructuredClone(JSContext* cx,
                                 JSStructuredCloneReader* reader, uint32_t idx)
{
  nsresult rv;
  nsCOMPtr<LabeledBlobService> lbs = 
    do_GetService("@mozilla.org/labeledblob-service;1", &rv);
  if (NS_FAILED(rv)) {
    return nullptr;
  }
  if(idx >= lbs->mLabeledBlobList.Length()) {
    return nullptr;
  }
  nsRefPtr<LabeledBlob> labeledBlob = lbs->mLabeledBlobList[idx];
  lbs->mLabeledBlobList.RemoveElementAt(idx);

  nsCOMPtr<nsIDOMBlob> blob = labeledBlob->Blob();
  nsRefPtr<Label> privacy   = labeledBlob->Privacy();
  nsRefPtr<Label> trust     = labeledBlob->Trust();
  nsRefPtr<LabeledBlob> b   = 
    new LabeledBlob(blob.get(), *(privacy.get()), *(trust.get()));

  return b->WrapObject(cx);
}

} // namespace dom
} // namespace mozilla
