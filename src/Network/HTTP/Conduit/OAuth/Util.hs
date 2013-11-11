{-# LANGUAGE DeriveFunctor #-}
{-# LANGUAGE RankNTypes    #-}
{-# LANGUAGE TupleSections #-}

module Network.HTTP.Conduit.OAuth.Util (
  view, over, iso, from, prism, preview, to, _Just, _Nothing
  ) where

import           Control.Applicative
import           Data.Functor.Contravariant
import           Data.Monoid
import           Data.Profunctor
import           Data.Profunctor.Unsafe
import           Unsafe.Coerce

-- mu Lens
--------------------------------------------------------------------------------

-- Lens: (forall f. Functor f => (a -> f a) -> (b -> f b))

newtype I a   = I { unI :: a } deriving ( Functor )
newtype K b a = K { unK :: b } deriving ( Functor )

instance Contravariant (K b) where
  contramap _ (K b) = K b

view :: (forall f. (Contravariant f, Functor f) => (a -> f b) -> s -> f t) -> s -> a
view inj = unK . inj K
{-# INLINE view #-}

over :: (forall f. Functor f => (a -> f b) -> s -> f t) -> (a -> b) -> (s -> t)
over inj f = unI . inj (I . f)
{-# INLINE over #-}

iso :: Profunctor p => (s -> a) -> (b -> t) -> p a b -> p s t
iso = dimap
{-# INLINE iso #-}

type AnIso s t a b = X a b a (I b) -> X a b s (I t)

withIso :: AnIso s t a b -> ((s -> a) -> (b -> t) -> r) -> r
withIso ai k = case ai (X id I) of
  X sa bt -> k sa (unI #. bt)
{-# INLINE withIso #-}

from :: Profunctor p => AnIso s t a b -> (p t s -> p b a)
from l = withIso l $ \ sa bt -> iso bt sa
{-# INLINE from #-}

data X a b s t = X (s -> a) (b -> t) deriving ( Functor )

instance Profunctor (X a b) where
  dimap f g (X sa bt) = X (sa . f) (g . bt)
  {-# INLINE dimap #-}
  lmap f (X sa bt) = X (sa . f) bt
  {-# INLINE lmap #-}
  rmap f (X sa bt) = X sa (f . bt)
  {-# INLINE rmap #-}
  ( #. ) _ = unsafeCoerce
  {-# INLINE ( #. ) #-}
  ( .# ) p _ = unsafeCoerce p
  {-# INLINE ( .# ) #-}

prism ::
  (Choice p, Applicative f) =>
  (b -> t) -> (s -> Either t a) -> p a (f b) -> p s (f t)
prism bt seta = dimap seta (either pure (fmap bt)) . right'
{-# INLINE prism #-}

foldMapOf
  :: (Profunctor p, Profunctor p1) =>
     (p1 a2 (K b a3) -> p a (K c a1)) -> p1 a2 b -> p a c
foldMapOf l f = unK #. l (K #. f)
{-# INLINE foldMapOf #-}

preview :: ((a -> K (First a) a) -> s -> K (First a) s) -> s -> Maybe a
preview l = getFirst #. foldMapOf l (First #. Just)
{-# INLINE preview #-}

data Void = Void Void

absurd :: Void -> a
absurd (Void v) = absurd v
{-# INLINE absurd #-}

coerce :: (Contravariant f, Functor f) => f a -> f b
coerce a = absurd <$> contramap absurd a
{-# INLINE coerce #-}

to :: (Functor f, Contravariant f, Profunctor p) =>
      (s -> a) -> p a (f x) -> p s (f y)
to k = dimap k coerce
{-# INLINE to #-}

_Just :: (Applicative f, Choice p) =>
         p a (f b) -> p (Maybe a) (f (Maybe b))
_Just = prism Just (maybe (Left Nothing) Right)
{-# INLINE _Just #-}

_Nothing :: (Applicative f, Choice p) =>
            p () (f b) -> p (Maybe a1) (f (Maybe a))
_Nothing = prism (const Nothing) $ maybe (Right ()) (const $ Left Nothing)
{-# INLINE _Nothing #-}
