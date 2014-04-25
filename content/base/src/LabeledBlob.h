/* -*- Mode: C++; tab-width: 2; indent-tabs-mode: nil; c-basic-offset: 2 -*- */
/* vim:set ts=2 sw=2 sts=2 et cindent: */
/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#ifndef mozilla_dom_LabeledBlob_h__
#define mozilla_dom_LabeledBlob_h__

#include "mozilla/Attributes.h"
#include "mozilla/ErrorResult.h"
#include "mozilla/dom/LabeledBlobBinding.h"
#include "nsCycleCollectionParticipant.h"
#include "nsTArray.h"
#include "nsWrapperCache.h"
#include "mozilla/dom/Label.h"
#include "nsIDOMFile.h"

struct JSContext;

namespace mozilla {
namespace dom {

class LabeledBlob MOZ_FINAL : public nsISupports
                            , public nsWrapperCache
{
public:
  NS_DECL_CYCLE_COLLECTING_ISUPPORTS
  NS_DECL_CYCLE_COLLECTION_SCRIPT_HOLDER_CLASS(LabeledBlob)

public:
  LabeledBlob(nsIDOMBlob* blob,
              mozilla::dom::Label& privacy, mozilla::dom::Label& trust);

  ~LabeledBlob() { }

  LabeledBlob* GetParentObject() const
  {
    return nullptr; //TODO: return something sensible here
  }

  JSObject* WrapObject(JSContext* aCx) MOZ_OVERRIDE
  {
    return LabeledBlobBinding::Wrap(aCx, this);
  }

  static already_AddRefed<LabeledBlob> Constructor(const GlobalObject& global, 
                                                   JSContext* cx,
                                                   nsIDOMBlob* blob,
                                                   ErrorResult& aRv);
  static already_AddRefed<LabeledBlob> Constructor(const GlobalObject& global,
                                                   JSContext* cx,
                                                   nsIDOMBlob* blob,
                                                   mozilla::dom::Label& privacy,
                                                   ErrorResult& aRv);
  static already_AddRefed<LabeledBlob> Constructor(const GlobalObject& global,
                                                   JSContext* cx,
                                                   nsIDOMBlob* blob,
                                                   mozilla::dom::Label& privacy,
                                                   mozilla::dom::Label& trust,
                                                   ErrorResult& aRv);

  // Mark this as resultNotAddRefed to return raw pointers
  already_AddRefed<Label> Privacy() const;

  // Mark this as resultNotAddRefed to return raw pointers
  already_AddRefed<Label> Trust() const;

  // Mark this as resultNotAddRefed to return raw pointers
  already_AddRefed<nsIDOMBlob> GetBlob(JSContext* cx, ErrorResult& aRv) const;

public: // Internal
  already_AddRefed<nsIDOMBlob> Blob() const;

  bool WriteStructuredClone(JSContext* cx, JSStructuredCloneWriter* writer);
  static JSObject* ReadStructuredClone(JSContext* cx, JSStructuredCloneReader* reader, uint32_t data);

private:
  nsRefPtr<Label> mPrivacy;
  nsRefPtr<Label> mTrust;
  nsCOMPtr<nsIDOMBlob> mBlob;
};

} // namespace dom
} // namespace mozilla

#endif // mozilla_dom_LabeledBlob_h__
