#ifndef mozilla_dom_LabeledBlobService_h__
#define mozilla_dom_LabeledBlobService_h__

#include "nsXPCOM.h"
#include "nsTArray.h"

namespace mozilla {
namespace dom {

class LabeledBlob;

#define LABELEDBLOBSERVICE_CONTRACTID "@mozilla.org/labeledblob-service;1"
#define LABELEDBLOBSERVICE_CID \
  { 0xac9737e0, 0xd873, 0x40aa, \
    { 0xb8, 0x6a, 0x6b, 0xce, 0x6d, 0xd4, 0x3d, 0xa2 }}

class LabeledBlobService : public nsISupports
{
public:
  NS_DECL_ISUPPORTS

  LabeledBlobService();
  virtual ~LabeledBlobService();

  nsTArray<nsRefPtr<LabeledBlob> > mLabeledBlobList;
};

} // namespace dom
} // namespace mozilla

#endif // mozilla_dom_LabeledBlobService_h__
